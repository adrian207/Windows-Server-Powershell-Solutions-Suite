#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Server Configuration Example Script

.DESCRIPTION
    This example script demonstrates how to configure a Windows Print Server
    with common settings including printer installation, driver management,
    and basic configuration.

.EXAMPLE
    .\Example-ConfigurePrintServer.ps1

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

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

Write-Host "=== Print Server Configuration Example ===" -ForegroundColor Cyan
Write-Host "This example demonstrates basic print server configuration" -ForegroundColor White

try {
    # Step 1: Check prerequisites
    Write-Host "`nStep 1: Checking prerequisites..." -ForegroundColor Yellow
    $prerequisites = Test-PrintServerPrerequisites
    if ($prerequisites) {
        Write-Host "Prerequisites check passed" -ForegroundColor Green
    } else {
        Write-Host "Prerequisites check failed" -ForegroundColor Red
        exit 1
    }
    
    # Step 2: Install print server role
    Write-Host "`nStep 2: Installing print server role..." -ForegroundColor Yellow
    $installResult = Install-PrintServerPrerequisites
    if ($installResult) {
        Write-Host "Print server role installed successfully" -ForegroundColor Green
    } else {
        Write-Host "Print server role installation failed" -ForegroundColor Red
        exit 1
    }
    
    # Step 3: Configure print server
    Write-Host "`nStep 3: Configuring print server..." -ForegroundColor Yellow
    Set-PrintServerConfiguration -EnableWebManagement -EnableBranchOfficeDirectPrinting
    Write-Host "Print server configuration completed" -ForegroundColor Green
    
    # Step 4: Install example printer drivers
    Write-Host "`nStep 4: Installing example printer drivers..." -ForegroundColor Yellow
    
    # Install generic text driver
    try {
        Install-PrintServerDriver -DriverName "Generic / Text Only" -FromWindowsUpdate
        Write-Host "Generic text driver installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "Could not install generic text driver: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Step 5: Create example printers
    Write-Host "`nStep 5: Creating example printers..." -ForegroundColor Yellow
    
    # Create local printer
    try {
        New-PrintServerPrinter -PrinterName "Example Local Printer" -DriverName "Generic / Text Only" -PortName "LPT1:" -Location "Office" -Comment "Example local printer" -Shared
        Write-Host "Example local printer created successfully" -ForegroundColor Green
    } catch {
        Write-Host "Could not create local printer: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Create network printer
    try {
        New-PrintServerPrinter -PrinterName "Example Network Printer" -DriverName "Generic / Text Only" -PortName "192.168.1.100" -Location "Office" -Comment "Example network printer" -Shared -Published
        Write-Host "Example network printer created successfully" -ForegroundColor Green
    } catch {
        Write-Host "Could not create network printer: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Step 6: Get print server status
    Write-Host "`nStep 6: Getting print server status..." -ForegroundColor Yellow
    $status = Get-PrintServerStatus
    Write-Host "Print server status retrieved successfully" -ForegroundColor Green
    
    # Display summary
    Write-Host "`n=== Configuration Summary ===" -ForegroundColor Cyan
    Write-Host "Computer Name: $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host "Print Server Installed: $($status.PrintServerInstalled)" -ForegroundColor White
    Write-Host "Spooler Service Status: $($status.SpoolerServiceStatus)" -ForegroundColor White
    Write-Host "Web Management Enabled: $($status.Configuration.WebManagementEnabled)" -ForegroundColor White
    Write-Host "Branch Office Direct Printing Enabled: $($status.Configuration.BranchOfficeDirectPrintingEnabled)" -ForegroundColor White
    Write-Host "Installed Printers: $($status.InstalledPrinters.Count)" -ForegroundColor White
    Write-Host "Installed Drivers: $($status.PrintDrivers.Count)" -ForegroundColor White
    
    # Display installed printers
    if ($status.InstalledPrinters.Count -gt 0) {
        Write-Host "`nInstalled Printers:" -ForegroundColor Yellow
        foreach ($printer in $status.InstalledPrinters) {
            Write-Host "  - $($printer.Name): $($printer.DriverName)" -ForegroundColor White
        }
    }
    
    Write-Host "`nPrint server configuration example completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "`nPrint server configuration example failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
