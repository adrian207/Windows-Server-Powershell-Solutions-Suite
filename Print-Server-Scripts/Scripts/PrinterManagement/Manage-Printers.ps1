#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Printer Management Script

.DESCRIPTION
    This script provides comprehensive printer management capabilities including
    adding, removing, configuring printers, and managing printer drivers.

.PARAMETER Action
    The action to perform (AddPrinter, RemovePrinter, ConfigurePrinter, InstallDriver, RemoveDriver, ListPrinters, ListDrivers)

.PARAMETER PrinterName
    The name of the printer

.PARAMETER DriverName
    The name of the printer driver

.PARAMETER PortName
    The port name for the printer

.PARAMETER Location
    The location description for the printer

.PARAMETER Comment
    Comment for the printer

.PARAMETER DriverPath
    Path to the driver files

.PARAMETER InfPath
    Path to the .inf file

.PARAMETER Architecture
    Architecture of the driver (x86, x64, ARM64)

.PARAMETER Shared
    Whether the printer should be shared

.PARAMETER Published
    Whether the printer should be published in Active Directory

.PARAMETER EnableBidirectional
    Enable bidirectional communication

.PARAMETER EnableKeepPrintedJobs
    Keep printed jobs in the queue

.PARAMETER EnableEnableDevQueryPrint
    Enable device query printing

.PARAMETER FromWindowsUpdate
    Install driver from Windows Update

.PARAMETER OutputPath
    Path to save reports

.PARAMETER GenerateReport
    Generate detailed printer report

.EXAMPLE
    .\Manage-Printers.ps1 -Action AddPrinter -PrinterName "Office Printer" -DriverName "Generic / Text Only" -PortName "LPT1:"

.EXAMPLE
    .\Manage-Printers.ps1 -Action InstallDriver -DriverName "HP LaserJet Pro" -DriverPath "C:\Drivers\HP" -InfPath "C:\Drivers\HP\hpcu118c.inf"

.EXAMPLE
    .\Manage-Printers.ps1 -Action ListPrinters -GenerateReport -OutputPath "C:\Reports\Printers.html"

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("AddPrinter", "RemovePrinter", "ConfigurePrinter", "InstallDriver", "RemoveDriver", "ListPrinters", "ListDrivers", "Report")]
    [string]$Action,
    
    [string]$PrinterName,
    
    [string]$DriverName,
    
    [string]$PortName,
    
    [string]$Location,
    
    [string]$Comment,
    
    [string]$DriverPath,
    
    [string]$InfPath,
    
    [ValidateSet("x86", "x64", "ARM64")]
    [string]$Architecture = "x64",
    
    [switch]$Shared,
    
    [switch]$Published,
    
    [switch]$EnableBidirectional,
    
    [switch]$EnableKeepPrintedJobs,
    
    [switch]$EnableEnableDevQueryPrint,
    
    [switch]$FromWindowsUpdate,
    
    [string]$OutputPath,
    
    [switch]$GenerateReport
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
$script:PrinterLog = @()
$script:StartTime = Get-Date

function Write-PrinterLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:PrinterLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Add-PrinterConfiguration {
    Write-PrinterLog "Adding printer: $PrinterName" "INFO"
    
    try {
        if (-not $PrinterName -or -not $DriverName -or -not $PortName) {
            throw "PrinterName, DriverName, and PortName are required for AddPrinter action"
        }
        
        New-PrintServerPrinter -PrinterName $PrinterName -DriverName $DriverName -PortName $PortName -Location $Location -Comment $Comment -Shared:$Shared -Published:$Published -EnableBidirectional:$EnableBidirectional -EnableKeepPrintedJobs:$EnableKeepPrintedJobs -EnableEnableDevQueryPrint:$EnableEnableDevQueryPrint
        
        Write-PrinterLog "Printer added successfully: $PrinterName" "SUCCESS"
        return $true
        
    } catch {
        Write-PrinterLog "Error adding printer: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-PrinterConfiguration {
    Write-PrinterLog "Removing printer: $PrinterName" "INFO"
    
    try {
        if (-not $PrinterName) {
            throw "PrinterName is required for RemovePrinter action"
        }
        
        Remove-PrintServerPrinter -PrinterName $PrinterName -RemoveDriver
        
        Write-PrinterLog "Printer removed successfully: $PrinterName" "SUCCESS"
        return $true
        
    } catch {
        Write-PrinterLog "Error removing printer: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-PrinterSettings {
    Write-PrinterLog "Configuring printer: $PrinterName" "INFO"
    
    try {
        if (-not $PrinterName) {
            throw "PrinterName is required for ConfigurePrinter action"
        }
        
        # Check if printer exists
        $printer = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if (-not $printer) {
            throw "Printer '$PrinterName' does not exist"
        }
        
        # Configure printer settings
        if ($Location) {
            Set-Printer -Name $PrinterName -Location $Location
            Write-PrinterLog "Location set for printer: $PrinterName" "SUCCESS"
        }
        
        if ($Comment) {
            Set-Printer -Name $PrinterName -Comment $Comment
            Write-PrinterLog "Comment set for printer: $PrinterName" "SUCCESS"
        }
        
        if ($Shared) {
            Set-Printer -Name $PrinterName -Shared $true
            Write-PrinterLog "Printer shared: $PrinterName" "SUCCESS"
        }
        
        if ($Published) {
            Set-Printer -Name $PrinterName -Published $true
            Write-PrinterLog "Printer published: $PrinterName" "SUCCESS"
        }
        
        if ($EnableBidirectional) {
            Set-Printer -Name $PrinterName -EnableBidirectional $true
            Write-PrinterLog "Bidirectional communication enabled for printer: $PrinterName" "SUCCESS"
        }
        
        if ($EnableKeepPrintedJobs) {
            Set-Printer -Name $PrinterName -KeepPrintedJobs $true
            Write-PrinterLog "Keep printed jobs enabled for printer: $PrinterName" "SUCCESS"
        }
        
        if ($EnableEnableDevQueryPrint) {
            Set-Printer -Name $PrinterName -EnableDevQueryPrint $true
            Write-PrinterLog "Device query printing enabled for printer: $PrinterName" "SUCCESS"
        }
        
        Write-PrinterLog "Printer configuration completed: $PrinterName" "SUCCESS"
        return $true
        
    } catch {
        Write-PrinterLog "Error configuring printer: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-PrinterDriver {
    Write-PrinterLog "Installing printer driver: $DriverName" "INFO"
    
    try {
        if (-not $DriverName) {
            throw "DriverName is required for InstallDriver action"
        }
        
        Install-PrintServerDriver -DriverName $DriverName -DriverPath $DriverPath -InfPath $InfPath -Architecture $Architecture -FromWindowsUpdate:$FromWindowsUpdate
        
        Write-PrinterLog "Driver installed successfully: $DriverName" "SUCCESS"
        return $true
        
    } catch {
        Write-PrinterLog "Error installing driver: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-PrinterDriver {
    Write-PrinterLog "Removing printer driver: $DriverName" "INFO"
    
    try {
        if (-not $DriverName) {
            throw "DriverName is required for RemoveDriver action"
        }
        
        Remove-PrintServerDriver -DriverName $DriverName -Force
        
        Write-PrinterLog "Driver removed successfully: $DriverName" "SUCCESS"
        return $true
        
    } catch {
        Write-PrinterLog "Error removing driver: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-PrinterList {
    Write-PrinterLog "Getting printer list..." "INFO"
    
    try {
        $printers = Get-Printer
        
        Write-Host "`n=== Installed Printers ===" -ForegroundColor Cyan
        Write-Host "Total Printers: $($printers.Count)" -ForegroundColor White
        
        if ($printers.Count -gt 0) {
            $printers | Format-Table Name, DriverName, PortName, Location, Shared, Published, PrinterStatus -AutoSize
        } else {
            Write-Host "No printers installed" -ForegroundColor Yellow
        }
        
        Write-PrinterLog "Printer list retrieved successfully" "SUCCESS"
        return $printers
        
    } catch {
        Write-PrinterLog "Error getting printer list: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-DriverList {
    Write-PrinterLog "Getting driver list..." "INFO"
    
    try {
        $drivers = Get-PrinterDriver
        
        Write-Host "`n=== Installed Printer Drivers ===" -ForegroundColor Cyan
        Write-Host "Total Drivers: $($drivers.Count)" -ForegroundColor White
        
        if ($drivers.Count -gt 0) {
            $drivers | Format-Table Name, DriverVersion, InfPath -AutoSize
        } else {
            Write-Host "No drivers installed" -ForegroundColor Yellow
        }
        
        Write-PrinterLog "Driver list retrieved successfully" "SUCCESS"
        return $drivers
        
    } catch {
        Write-PrinterLog "Error getting driver list: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function New-PrinterReport {
    Write-PrinterLog "Generating printer report..." "INFO"
    
    try {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $scriptPath "Printer-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        }
        
        $report = Get-PrintServerReport -OutputPath $OutputPath -IncludePrintJobs -IncludeDrivers
        
        if ($report) {
            Write-Host "`n=== Printer Report Generated ===" -ForegroundColor Cyan
            Write-Host "Report Path: $OutputPath" -ForegroundColor White
            Write-Host "Report Type: HTML" -ForegroundColor White
            Write-Host "Total Printers: $($report.Summary.TotalPrinters)" -ForegroundColor White
            Write-Host "Total Drivers: $($report.Summary.TotalDrivers)" -ForegroundColor White
            Write-Host "Total Print Jobs: $($report.Summary.TotalPrintJobs)" -ForegroundColor White
        }
        
        Write-PrinterLog "Printer report generated successfully" "SUCCESS"
        return $report
        
    } catch {
        Write-PrinterLog "Error generating printer report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-PrinterLog {
    $logPath = Join-Path $scriptPath "Printer-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:PrinterLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-PrinterLog "Printer log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save printer log: $($_.Exception.Message)"
    }
}

# Main printer management process
try {
    Write-PrinterLog "Starting printer management..." "INFO"
    Write-PrinterLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "AddPrinter" {
            $result = Add-PrinterConfiguration
            if ($result) {
                Write-Host "`nPrinter added successfully: $PrinterName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to add printer: $PrinterName" -ForegroundColor Red
            }
        }
        
        "RemovePrinter" {
            $result = Remove-PrinterConfiguration
            if ($result) {
                Write-Host "`nPrinter removed successfully: $PrinterName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to remove printer: $PrinterName" -ForegroundColor Red
            }
        }
        
        "ConfigurePrinter" {
            $result = Set-PrinterSettings
            if ($result) {
                Write-Host "`nPrinter configured successfully: $PrinterName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to configure printer: $PrinterName" -ForegroundColor Red
            }
        }
        
        "InstallDriver" {
            $result = Install-PrinterDriver
            if ($result) {
                Write-Host "`nDriver installed successfully: $DriverName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to install driver: $DriverName" -ForegroundColor Red
            }
        }
        
        "RemoveDriver" {
            $result = Remove-PrinterDriver
            if ($result) {
                Write-Host "`nDriver removed successfully: $DriverName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to remove driver: $DriverName" -ForegroundColor Red
            }
        }
        
        "ListPrinters" {
            $printers = Get-PrinterList
            if ($GenerateReport) {
                $report = New-PrinterReport
            }
        }
        
        "ListDrivers" {
            $drivers = Get-DriverList
            if ($GenerateReport) {
                $report = New-PrinterReport
            }
        }
        
        "Report" {
            $report = New-PrinterReport
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-PrinterLog "Printer management completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== Printer Management Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save printer log
    Save-PrinterLog
    
    Write-Host "`nPrinter management completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-PrinterLog "Printer management failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save printer log
    Save-PrinterLog
    
    Write-Host "`nPrinter management failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the printer log for details." -ForegroundColor Yellow
    
    exit 1
}
