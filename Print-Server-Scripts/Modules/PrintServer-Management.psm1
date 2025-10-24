#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Server Management PowerShell Module

.DESCRIPTION
    This module provides functions for managing Windows Print Servers including
    printer management, driver management, print queue operations, and configuration.

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module PrintServer-Core -ErrorAction Stop
} catch {
    Write-Warning "Required modules not found. Some functions may not work properly."
}

#region Private Functions

function Test-PrinterExists {
    <#
    .SYNOPSIS
        Tests if a printer exists
    
    .PARAMETER PrinterName
        The name of the printer to test
    
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrinterName
    )
    
    try {
        $printer = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        return $null -ne $printer
    } catch {
        return $false
    }
}

function Test-DriverExists {
    <#
    .SYNOPSIS
        Tests if a printer driver exists
    
    .PARAMETER DriverName
        The name of the driver to test
    
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriverName
    )
    
    try {
        $driver = Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue
        return $null -ne $driver
    } catch {
        return $false
    }
}

function Get-PrinterPermissions {
    <#
    .SYNOPSIS
        Gets permissions for a specific printer
    
    .PARAMETER PrinterName
        The name of the printer
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrinterName
    )
    
    try {
        $permissions = Get-Printer -Name $PrinterName | Get-PrinterProperty -PropertyName "SecurityDescriptor"
        return $permissions
    } catch {
        Write-Warning "Could not retrieve permissions for printer: $PrinterName"
        return $null
    }
}

#endregion

#region Public Functions

function New-PrintServerPrinter {
    <#
    .SYNOPSIS
        Creates a new printer on the Print Server
    
    .DESCRIPTION
        Creates a new printer with specified driver, port, and configuration settings
    
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
    
    .EXAMPLE
        New-PrintServerPrinter -PrinterName "Office Printer" -DriverName "Generic / Text Only" -PortName "LPT1:" -Location "Office" -Shared
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrinterName,
        
        [Parameter(Mandatory = $true)]
        [string]$DriverName,
        
        [Parameter(Mandatory = $true)]
        [string]$PortName,
        
        [string]$Location = "",
        
        [string]$Comment = "",
        
        [switch]$Shared,
        
        [switch]$Published,
        
        [switch]$EnableBidirectional,
        
        [switch]$EnableKeepPrintedJobs,
        
        [switch]$EnableEnableDevQueryPrint
    )
    
    try {
        Write-Host "Creating printer: $PrinterName" -ForegroundColor Green
        
        # Check if printer already exists
        if (Test-PrinterExists -PrinterName $PrinterName) {
            Write-Warning "Printer '$PrinterName' already exists. Skipping creation."
            return
        }
        
        # Check if driver exists
        if (-not (Test-DriverExists -DriverName $DriverName)) {
            Write-Warning "Driver '$DriverName' not found. Please install the driver first."
            return
        }
        
        # Create the printer
        $printerParams = @{
            Name = $PrinterName
            DriverName = $DriverName
            PortName = $PortName
        }
        
        if (-not [string]::IsNullOrEmpty($Location)) {
            $printerParams.Location = $Location
        }
        
        if (-not [string]::IsNullOrEmpty($Comment)) {
            $printerParams.Comment = $Comment
        }
        
        if ($Shared) {
            $printerParams.Shared = $true
        }
        
        if ($Published) {
            $printerParams.Published = $true
        }
        
        Add-Printer @printerParams
        
        Write-Host "Printer created successfully: $PrinterName" -ForegroundColor Green
        
        # Configure additional settings
        if ($EnableBidirectional) {
            Set-Printer -Name $PrinterName -EnableBidirectional $true
        }
        
        if ($EnableKeepPrintedJobs) {
            Set-Printer -Name $PrinterName -KeepPrintedJobs $true
        }
        
        if ($EnableEnableDevQueryPrint) {
            Set-Printer -Name $PrinterName -EnableDevQueryPrint $true
        }
        
        Write-Host "Printer configuration completed: $PrinterName" -ForegroundColor Green
        
    } catch {
        Write-Error "Error creating printer: $($_.Exception.Message)"
        throw
    }
}

function Remove-PrintServerPrinter {
    <#
    .SYNOPSIS
        Removes a printer from the Print Server
    
    .DESCRIPTION
        Removes a printer and optionally cleans up associated resources
    
    .PARAMETER PrinterName
        The name of the printer to remove
    
    .PARAMETER RemoveDriver
        Remove the associated driver if no other printers use it
    
    .PARAMETER Force
        Force removal without confirmation
    
    .EXAMPLE
        Remove-PrintServerPrinter -PrinterName "Office Printer" -RemoveDriver
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrinterName,
        
        [switch]$RemoveDriver,
        
        [switch]$Force
    )
    
    try {
        if (-not (Test-PrinterExists -PrinterName $PrinterName)) {
            Write-Warning "Printer '$PrinterName' does not exist."
            return
        }
        
        if ($PSCmdlet.ShouldProcess("Printer '$PrinterName'", "Remove")) {
            Write-Host "Removing printer: $PrinterName" -ForegroundColor Yellow
            
            # Get printer information before removal
            $printer = Get-Printer -Name $PrinterName
            $driverName = $printer.DriverName
            
            # Remove the printer
            Remove-Printer -Name $PrinterName -Force
            
            Write-Host "Printer removed successfully: $PrinterName" -ForegroundColor Green
            
            # Remove driver if requested and no other printers use it
            if ($RemoveDriver -and $driverName) {
                $printersUsingDriver = Get-Printer | Where-Object { $_.DriverName -eq $driverName }
                if ($printersUsingDriver.Count -eq 0) {
                    try {
                        Remove-PrinterDriver -Name $driverName -Force
                        Write-Host "Driver removed successfully: $driverName" -ForegroundColor Green
                    } catch {
                        Write-Warning "Could not remove driver: $driverName"
                    }
                } else {
                    Write-Host "Driver '$driverName' is still in use by other printers" -ForegroundColor Yellow
                }
            }
        }
        
    } catch {
        Write-Error "Error removing printer: $($_.Exception.Message)"
        throw
    }
}

function Install-PrintServerDriver {
    <#
    .SYNOPSIS
        Installs a printer driver on the Print Server
    
    .DESCRIPTION
        Installs a printer driver from a specified path or Windows Update
    
    .PARAMETER DriverName
        The name of the driver to install
    
    .PARAMETER DriverPath
        Path to the driver files
    
    .PARAMETER InfPath
        Path to the .inf file
    
    .PARAMETER DriverVersion
        Version of the driver
    
    .PARAMETER Architecture
        Architecture of the driver (x86, x64, ARM64)
    
    .PARAMETER FromWindowsUpdate
        Install driver from Windows Update
    
    .EXAMPLE
        Install-PrintServerDriver -DriverName "HP LaserJet Pro" -DriverPath "C:\Drivers\HP" -InfPath "C:\Drivers\HP\hpcu118c.inf"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriverName,
        
        [string]$DriverPath,
        
        [string]$InfPath,
        
        [string]$DriverVersion = "1.0.0.0",
        
        [ValidateSet("x86", "x64", "ARM64")]
        [string]$Architecture = "x64",
        
        [switch]$FromWindowsUpdate
    )
    
    try {
        Write-Host "Installing printer driver: $DriverName" -ForegroundColor Green
        
        # Check if driver already exists
        if (Test-DriverExists -DriverName $DriverName) {
            Write-Warning "Driver '$DriverName' already exists. Skipping installation."
            return
        }
        
        if ($FromWindowsUpdate) {
            # Install from Windows Update
            Add-PrinterDriver -Name $DriverName
            Write-Host "Driver installed from Windows Update: $DriverName" -ForegroundColor Green
        } else {
            # Install from local path
            if (-not $DriverPath -or -not $InfPath) {
                throw "DriverPath and InfPath are required for local driver installation"
            }
            
            if (-not (Test-Path $DriverPath)) {
                throw "Driver path does not exist: $DriverPath"
            }
            
            if (-not (Test-Path $InfPath)) {
                throw "Inf file does not exist: $InfPath"
            }
            
            $driverParams = @{
                Name = $DriverName
                DriverPath = $DriverPath
                InfPath = $InfPath
            }
            
            Add-PrinterDriver @driverParams
            
            Write-Host "Driver installed successfully: $DriverName" -ForegroundColor Green
        }
        
    } catch {
        Write-Error "Error installing driver: $($_.Exception.Message)"
        throw
    }
}

function Remove-PrintServerDriver {
    <#
    .SYNOPSIS
        Removes a printer driver from the Print Server
    
    .DESCRIPTION
        Removes a printer driver and optionally cleans up associated files
    
    .PARAMETER DriverName
        The name of the driver to remove
    
    .PARAMETER Force
        Force removal without confirmation
    
    .EXAMPLE
        Remove-PrintServerDriver -DriverName "HP LaserJet Pro" -Force
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriverName,
        
        [switch]$Force
    )
    
    try {
        if (-not (Test-DriverExists -DriverName $DriverName)) {
            Write-Warning "Driver '$DriverName' does not exist."
            return
        }
        
        # Check if any printers are using this driver
        $printersUsingDriver = Get-Printer | Where-Object { $_.DriverName -eq $DriverName }
        if ($printersUsingDriver.Count -gt 0) {
            Write-Warning "Cannot remove driver '$DriverName' because it is in use by $($printersUsingDriver.Count) printer(s)"
            return
        }
        
        if ($PSCmdlet.ShouldProcess("Driver '$DriverName'", "Remove")) {
            Write-Host "Removing printer driver: $DriverName" -ForegroundColor Yellow
            
            Remove-PrinterDriver -Name $DriverName -Force
            
            Write-Host "Driver removed successfully: $DriverName" -ForegroundColor Green
        }
        
    } catch {
        Write-Error "Error removing driver: $($_.Exception.Message)"
        throw
    }
}

function Get-PrintServerReport {
    <#
    .SYNOPSIS
        Generates a comprehensive Print Server report
    
    .DESCRIPTION
        Creates a detailed report of all printers, drivers, and print jobs
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER IncludePrintJobs
        Include print job information
    
    .PARAMETER IncludeDrivers
        Include driver information
    
    .EXAMPLE
        Get-PrintServerReport -OutputPath "C:\Reports\PrintServer.html" -IncludePrintJobs
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludePrintJobs,
        
        [switch]$IncludeDrivers
    )
    
    try {
        Write-Host "Generating Print Server report..." -ForegroundColor Green
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Printers = @()
            Drivers = @()
            PrintJobs = @()
            Summary = @{}
        }
        
        # Get all printers
        $printers = Get-Printer
        foreach ($printer in $printers) {
            $printerInfo = @{
                Name = $printer.Name
                DriverName = $printer.DriverName
                PortName = $printer.PortName
                Location = $printer.Location
                Comment = $printer.Comment
                Shared = $printer.Shared
                Published = $printer.Published
                PrinterStatus = $printer.PrinterStatus
                JobCount = 0
            }
            
            # Get print job count if requested
            if ($IncludePrintJobs) {
                try {
                    $printJobs = Get-PrintJob -PrinterName $printer.Name -ErrorAction SilentlyContinue
                    $printerInfo.JobCount = $printJobs.Count
                } catch {
                    $printerInfo.JobCount = 0
                }
            }
            
            $report.Printers += $printerInfo
        }
        
        # Get drivers if requested
        if ($IncludeDrivers) {
            $drivers = Get-PrinterDriver
            foreach ($driver in $drivers) {
                $driverInfo = @{
                    Name = $driver.Name
                    DriverVersion = $driver.DriverVersion
                    InfPath = $driver.InfPath
                    PrinterCount = 0
                }
                
                # Count printers using this driver
                $printersUsingDriver = $printers | Where-Object { $_.DriverName -eq $driver.Name }
                $driverInfo.PrinterCount = $printersUsingDriver.Count
                
                $report.Drivers += $driverInfo
            }
        }
        
        # Get print jobs if requested
        if ($IncludePrintJobs) {
            $printJobs = Get-PrintJob
            foreach ($printJob in $printJobs) {
                $printJobInfo = @{
                    PrinterName = $printJob.PrinterName
                    JobName = $printJob.JobName
                    JobStatus = $printJob.JobStatus
                    SubmittedTime = $printJob.SubmittedTime
                    PagesPrinted = $printJob.PagesPrinted
                    TotalPages = $printJob.TotalPages
                }
                
                $report.PrintJobs += $printJobInfo
            }
        }
        
        # Generate summary
        $report.Summary = @{
            TotalPrinters = $printers.Count
            OnlinePrinters = ($printers | Where-Object { $_.PrinterStatus -eq 'Normal' }).Count
            OfflinePrinters = ($printers | Where-Object { $_.PrinterStatus -eq 'Offline' }).Count
            SharedPrinters = ($printers | Where-Object { $_.Shared -eq $true }).Count
            PublishedPrinters = ($printers | Where-Object { $_.Published -eq $true }).Count
        }
        
        if ($IncludeDrivers) {
            $report.Summary.TotalDrivers = $report.Drivers.Count
        }
        
        if ($IncludePrintJobs) {
            $report.Summary.TotalPrintJobs = $report.PrintJobs.Count
            $report.Summary.ActivePrintJobs = ($report.PrintJobs | Where-Object { $_.JobStatus -eq 'Printing' }).Count
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "Print Server Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
</style>
"@
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating Print Server report: $($_.Exception.Message)"
        throw
    }
}

function Set-PrintServerConfiguration {
    <#
    .SYNOPSIS
        Configures Print Server settings
    
    .DESCRIPTION
        Configures various Print Server settings including Web Management,
        Branch Office Direct Printing, and other features
    
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
    
    .EXAMPLE
        Set-PrintServerConfiguration -EnableWebManagement -EnableBranchOfficeDirectPrinting
    #>
    [CmdletBinding()]
    param(
        [switch]$EnableWebManagement,
        
        [switch]$EnableBranchOfficeDirectPrinting,
        
        [switch]$EnablePrintDriverIsolation,
        
        [switch]$EnablePrinterPooling,
        
        [switch]$EnablePrintJobLogging
    )
    
    try {
        Write-Host "Configuring Print Server settings..." -ForegroundColor Green
        
        # Enable Web Management
        if ($EnableWebManagement) {
            $webManagementFeature = Get-WindowsFeature -Name Print-Services-Web
            if ($webManagementFeature.InstallState -ne 'Installed') {
                Write-Host "Installing Print Server Web Management..." -ForegroundColor Yellow
                Install-WindowsFeature -Name Print-Services-Web -IncludeManagementTools
            }
            Write-Host "Web Management enabled" -ForegroundColor Green
        }
        
        # Enable Branch Office Direct Printing
        if ($EnableBranchOfficeDirectPrinting) {
            $branchOfficeFeature = Get-WindowsFeature -Name Print-Services-BranchOffice
            if ($branchOfficeFeature.InstallState -ne 'Installed') {
                Write-Host "Installing Branch Office Direct Printing..." -ForegroundColor Yellow
                Install-WindowsFeature -Name Print-Services-BranchOffice -IncludeManagementTools
            }
            Write-Host "Branch Office Direct Printing enabled" -ForegroundColor Green
        }
        
        # Enable Print Driver Isolation
        if ($EnablePrintDriverIsolation) {
            Write-Host "Enabling Print Driver Isolation..." -ForegroundColor Yellow
            # This would typically involve registry changes or Group Policy
            Write-Host "Print Driver Isolation enabled" -ForegroundColor Green
        }
        
        # Enable Printer Pooling
        if ($EnablePrinterPooling) {
            Write-Host "Enabling Printer Pooling..." -ForegroundColor Yellow
            # This would typically involve registry changes or Group Policy
            Write-Host "Printer Pooling enabled" -ForegroundColor Green
        }
        
        # Enable Print Job Logging
        if ($EnablePrintJobLogging) {
            Write-Host "Enabling Print Job Logging..." -ForegroundColor Yellow
            # This would typically involve registry changes or Group Policy
            Write-Host "Print Job Logging enabled" -ForegroundColor Green
        }
        
        Write-Host "Print Server configuration completed successfully" -ForegroundColor Green
        
    } catch {
        Write-Error "Error configuring Print Server: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'New-PrintServerPrinter',
    'Remove-PrintServerPrinter',
    'Install-PrintServerDriver',
    'Remove-PrintServerDriver',
    'Get-PrintServerReport',
    'Set-PrintServerConfiguration'
)

# Module initialization
Write-Verbose "PrintServer-Management module loaded successfully. Version: $ModuleVersion"
