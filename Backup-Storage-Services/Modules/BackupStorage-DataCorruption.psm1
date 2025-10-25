#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Data Corruption Detection PowerShell Module

.DESCRIPTION
    This module provides comprehensive data corruption detection capabilities
    including disk error detection, file system integrity checks, and automated repair.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-DiskIntegrity {
    <#
    .SYNOPSIS
        Tests disk integrity using chkdsk
    #>
    [CmdletBinding()]
    param(
        [string]$DriveLetter,
        [switch]$ScanOnly
    )
    
    try {
        $chkdskCommand = "chkdsk $DriveLetter"
        if ($ScanOnly) {
            $chkdskCommand += " /scan"
        } else {
            $chkdskCommand += " /f"
        }
        
        Write-Verbose "Running: $chkdskCommand"
        $result = Invoke-Expression $chkdskCommand
        
        return @{
            Success = $true
            Command = $chkdskCommand
            Output = $result
        }
    } catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
            Command = $chkdskCommand
        }
    }
}

function Get-DiskErrors {
    <#
    .SYNOPSIS
        Gets disk errors using WMI
    #>
    [CmdletBinding()]
    param()
    
    try {
        $diskErrors = @()
        
        # Get physical disk errors
        $physicalDisks = Get-WmiObject -Class Win32_DiskDrive -ErrorAction SilentlyContinue
        foreach ($disk in $physicalDisks) {
            if ($disk.Status -ne "OK") {
                $diskErrors += @{
                    Type = "Physical Disk"
                    DeviceID = $disk.DeviceID
                    Status = $disk.Status
                    Model = $disk.Model
                    Size = $disk.Size
                }
            }
        }
        
        # Get logical disk errors
        $logicalDisks = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction SilentlyContinue
        foreach ($disk in $logicalDisks) {
            if ($disk.Status -ne "OK") {
                $diskErrors += @{
                    Type = "Logical Disk"
                    DeviceID = $disk.DeviceID
                    Status = $disk.Status
                    Size = $disk.Size
                    FreeSpace = $disk.FreeSpace
                }
            }
        }
        
        return $diskErrors
    } catch {
        Write-Warning "Error getting disk errors: $($_.Exception.Message)"
        return @()
    }
}

#endregion

#region Public Functions

function Test-DataCorruption {
    <#
    .SYNOPSIS
        Tests for data corruption on specified drives
    
    .DESCRIPTION
        This function performs comprehensive data corruption detection
        including file system checks, disk integrity tests, and error scanning.
    
    .PARAMETER DriveLetters
        Array of drive letters to test (default: all fixed drives)
    
    .PARAMETER ScanOnly
        Only scan for errors without attempting repairs
    
    .PARAMETER IncludeSystemDrive
        Include the system drive in the scan
    
    .PARAMETER DetailedReport
        Generate detailed corruption report
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-DataCorruption
    
    .EXAMPLE
        Test-DataCorruption -DriveLetters @("C:", "D:") -ScanOnly
    
    .EXAMPLE
        Test-DataCorruption -IncludeSystemDrive -DetailedReport
    #>
    [CmdletBinding()]
    param(
        [string[]]$DriveLetters,
        
        [switch]$ScanOnly,
        
        [switch]$IncludeSystemDrive,
        
        [switch]$DetailedReport
    )
    
    try {
        Write-Verbose "Starting data corruption detection..."
        
        # Determine drives to test
        if (-not $DriveLetters) {
            $DriveLetters = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { 
                $_.DriveType -eq 3 -and $_.Size -gt 0 
            } | Select-Object -ExpandProperty DeviceID
            
            if (-not $IncludeSystemDrive) {
                $DriveLetters = $DriveLetters | Where-Object { $_ -ne "C:" }
            }
        }
        
        $corruptionResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DriveLetters = $DriveLetters
            ScanOnly = $ScanOnly
            DriveResults = @()
            DiskErrors = @()
            Summary = @{}
        }
        
        # Get disk errors
        $corruptionResults.DiskErrors = Get-DiskErrors
        
        # Test each drive
        foreach ($drive in $DriveLetters) {
            Write-Verbose "Testing drive: $drive"
            
            $driveResult = @{
                DriveLetter = $drive
                FileSystemCheck = $null
                DiskIntegrity = $null
                Errors = @()
                Warnings = @()
            }
            
            # Check file system
            try {
                $fsCheck = Test-DiskIntegrity -DriveLetter $drive -ScanOnly:$ScanOnly
                $driveResult.FileSystemCheck = $fsCheck
                
                if (-not $fsCheck.Success) {
                    $driveResult.Errors += "File system check failed: $($fsCheck.Error)"
                }
            } catch {
                $driveResult.Errors += "File system check error: $($_.Exception.Message)"
            }
            
            # Check disk integrity
            try {
                $integrityCheck = Test-DiskIntegrity -DriveLetter $drive -ScanOnly:$ScanOnly
                $driveResult.DiskIntegrity = $integrityCheck
                
                if (-not $integrityCheck.Success) {
                    $driveResult.Errors += "Disk integrity check failed: $($integrityCheck.Error)"
                }
            } catch {
                $driveResult.Errors += "Disk integrity check error: $($_.Exception.Message)"
            }
            
            # Check for specific corruption indicators
            try {
                $diskInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction SilentlyContinue
                if ($diskInfo) {
                    if ($diskInfo.Status -ne "OK") {
                        $driveResult.Errors += "Drive status is not OK: $($diskInfo.Status)"
                    }
                    
                    # Check for low free space (can cause corruption)
                    $freeSpacePercent = ($diskInfo.FreeSpace / $diskInfo.Size) * 100
                    if ($freeSpacePercent -lt 10) {
                        $driveResult.Warnings += "Low free space: $([math]::Round($freeSpacePercent, 2))%"
                    }
                }
            } catch {
                $driveResult.Warnings += "Could not get drive information: $($_.Exception.Message)"
            }
            
            $corruptionResults.DriveResults += [PSCustomObject]$driveResult
        }
        
        # Generate summary
        $totalErrors = ($corruptionResults.DriveResults | ForEach-Object { $_.Errors.Count } | Measure-Object -Sum).Sum
        $totalWarnings = ($corruptionResults.DriveResults | ForEach-Object { $_.Warnings.Count } | Measure-Object -Sum).Sum
        
        $corruptionResults.Summary = @{
            TotalDrives = $DriveLetters.Count
            DrivesWithErrors = ($corruptionResults.DriveResults | Where-Object { $_.Errors.Count -gt 0 }).Count
            DrivesWithWarnings = ($corruptionResults.DriveResults | Where-Object { $_.Warnings.Count -gt 0 }).Count
            TotalErrors = $totalErrors
            TotalWarnings = $totalWarnings
            DiskErrors = $corruptionResults.DiskErrors.Count
            OverallStatus = if ($totalErrors -eq 0) { "Healthy" } elseif ($totalErrors -lt 3) { "Warning" } else { "Critical" }
        }
        
        Write-Verbose "Data corruption detection completed"
        return [PSCustomObject]$corruptionResults
        
    } catch {
        Write-Error "Error during data corruption detection: $($_.Exception.Message)"
        return $null
    }
}

function Repair-DataCorruption {
    <#
    .SYNOPSIS
        Repairs data corruption on specified drives
    
    .DESCRIPTION
        This function attempts to repair data corruption using various methods
        including chkdsk repairs, file system fixes, and disk error corrections.
    
    .PARAMETER DriveLetters
        Array of drive letters to repair
    
    .PARAMETER RepairMethod
        Repair method to use (Chkdsk, SFC, DISM)
    
    .PARAMETER ConfirmRepair
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Repair-DataCorruption -DriveLetters @("D:") -RepairMethod "Chkdsk" -ConfirmRepair
    
    .NOTES
        WARNING: Repair operations can be destructive and may cause data loss.
        Always backup important data before running repairs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$DriveLetters,
        
        [ValidateSet("Chkdsk", "SFC", "DISM", "All")]
        [string]$RepairMethod = "Chkdsk",
        
        [switch]$ConfirmRepair
    )
    
    if (-not $ConfirmRepair) {
        throw "You must specify -ConfirmRepair to proceed with this potentially destructive operation."
    }
    
    try {
        Write-Verbose "Starting data corruption repair..."
        
        $repairResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DriveLetters = $DriveLetters
            RepairMethod = $RepairMethod
            DriveResults = @()
            Summary = @{}
        }
        
        foreach ($drive in $DriveLetters) {
            Write-Verbose "Repairing drive: $drive"
            
            $driveResult = @{
                DriveLetter = $drive
                ChkdskResult = $null
                SFCResult = $null
                DISMResult = $null
                Errors = @()
                Success = $false
            }
            
            # Run chkdsk repair
            if ($RepairMethod -eq "Chkdsk" -or $RepairMethod -eq "All") {
                try {
                    $chkdskResult = Test-DiskIntegrity -DriveLetter $drive -ScanOnly:$false
                    $driveResult.ChkdskResult = $chkdskResult
                    
                    if ($chkdskResult.Success) {
                        Write-Verbose "Chkdsk repair completed for drive: $drive"
                    } else {
                        $driveResult.Errors += "Chkdsk repair failed: $($chkdskResult.Error)"
                    }
                } catch {
                    $driveResult.Errors += "Chkdsk repair error: $($_.Exception.Message)"
                }
            }
            
            # Run System File Checker (SFC) for system drive
            if (($RepairMethod -eq "SFC" -or $RepairMethod -eq "All") -and $drive -eq "C:") {
                try {
                    Write-Verbose "Running System File Checker..."
                    $sfcResult = & sfc /scannow
                    $driveResult.SFCResult = @{
                        Success = $true
                        Output = $sfcResult
                    }
                    Write-Verbose "SFC scan completed"
                } catch {
                    $driveResult.Errors += "SFC scan error: $($_.Exception.Message)"
                }
            }
            
            # Run DISM repair for system drive
            if (($RepairMethod -eq "DISM" -or $RepairMethod -eq "All") -and $drive -eq "C:") {
                try {
                    Write-Verbose "Running DISM repair..."
                    $dismResult = & dism /online /cleanup-image /restorehealth
                    $driveResult.DISMResult = @{
                        Success = $true
                        Output = $dismResult
                    }
                    Write-Verbose "DISM repair completed"
                } catch {
                    $driveResult.Errors += "DISM repair error: $($_.Exception.Message)"
                }
            }
            
            # Determine overall success
            $driveResult.Success = ($driveResult.Errors.Count -eq 0)
            
            $repairResults.DriveResults += [PSCustomObject]$driveResult
        }
        
        # Generate summary
        $successfulRepairs = ($repairResults.DriveResults | Where-Object { $_.Success }).Count
        $totalErrors = ($repairResults.DriveResults | ForEach-Object { $_.Errors.Count } | Measure-Object -Sum).Sum
        
        $repairResults.Summary = @{
            TotalDrives = $DriveLetters.Count
            SuccessfulRepairs = $successfulRepairs
            FailedRepairs = $DriveLetters.Count - $successfulRepairs
            TotalErrors = $totalErrors
            OverallSuccess = ($totalErrors -eq 0)
        }
        
        Write-Verbose "Data corruption repair completed"
        return [PSCustomObject]$repairResults
        
    } catch {
        Write-Error "Error during data corruption repair: $($_.Exception.Message)"
        return $null
    }
}

function Get-DiskHealthReport {
    <#
    .SYNOPSIS
        Generates a comprehensive disk health report
    
    .DESCRIPTION
        This function creates a detailed report of disk health including
        corruption status, error counts, and recommendations.
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER IncludeRecommendations
        Include repair recommendations in the report
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-DiskHealthReport -OutputPath "C:\Reports\DiskHealth.html"
    
    .EXAMPLE
        Get-DiskHealthReport -IncludeRecommendations
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludeRecommendations
    )
    
    try {
        Write-Verbose "Generating disk health report..."
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            CorruptionTest = Test-DataCorruption -DetailedReport
            DiskErrors = Get-DiskErrors
            PhysicalDisks = @()
            LogicalDisks = @()
            Recommendations = @()
        }
        
        # Get physical disk information
        $physicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
        foreach ($disk in $physicalDisks) {
            $report.PhysicalDisks += @{
                FriendlyName = $disk.FriendlyName
                Size = $disk.Size
                HealthStatus = $disk.HealthStatus
                OperationalStatus = $disk.OperationalStatus
                Usage = $disk.Usage
                BusType = $disk.BusType
                MediaType = $disk.MediaType
            }
        }
        
        # Get logical disk information
        $logicalDisks = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction SilentlyContinue
        foreach ($disk in $logicalDisks) {
            $report.LogicalDisks += @{
                DeviceID = $disk.DeviceID
                Size = $disk.Size
                FreeSpace = $disk.FreeSpace
                FileSystem = $disk.FileSystem
                Status = $disk.Status
                VolumeName = $disk.VolumeName
            }
        }
        
        # Generate recommendations
        if ($IncludeRecommendations) {
            if ($report.CorruptionTest.Summary.TotalErrors -gt 0) {
                $report.Recommendations += "Run Repair-DataCorruption to fix detected errors"
            }
            
            $unhealthyDisks = $report.PhysicalDisks | Where-Object { $_.HealthStatus -ne "Healthy" }
            if ($unhealthyDisks) {
                $report.Recommendations += "Replace unhealthy physical disks: $($unhealthyDisks.FriendlyName -join ', ')"
            }
            
            $lowSpaceDisks = $report.LogicalDisks | Where-Object { 
                $_.FreeSpace -lt ($_.Size * 0.1) -and $_.Size -gt 0 
            }
            if ($lowSpaceDisks) {
                $report.Recommendations += "Free up space on drives with low free space: $($lowSpaceDisks.DeviceID -join ', ')"
            }
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "Disk Health Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #dc3545; padding-bottom: 10px; }
h2 { color: #dc3545; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.healthy { color: #28a745; font-weight: bold; }
.warning { color: #ffc107; font-weight: bold; }
.critical { color: #dc3545; font-weight: bold; }
.recommendation { background-color: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
</style>
"@
            
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Verbose "Disk health report saved to: $OutputPath"
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating disk health report: $($_.Exception.Message)"
        return $null
    }
}

function Start-CorruptionMonitoring {
    <#
    .SYNOPSIS
        Starts continuous corruption monitoring
    
    .DESCRIPTION
        This function starts a continuous monitoring process that periodically
        checks for data corruption and alerts when issues are detected.
    
    .PARAMETER DriveLetters
        Array of drive letters to monitor
    
    .PARAMETER IntervalMinutes
        Monitoring interval in minutes (default: 60)
    
    .PARAMETER AlertThreshold
        Number of errors before alerting (default: 1)
    
    .PARAMETER LogPath
        Path to save monitoring logs
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Start-CorruptionMonitoring -DriveLetters @("C:", "D:") -IntervalMinutes 30
    
    .EXAMPLE
        Start-CorruptionMonitoring -IntervalMinutes 60 -AlertThreshold 3 -LogPath "C:\Logs\CorruptionMonitor.log"
    #>
    [CmdletBinding()]
    param(
        [string[]]$DriveLetters,
        
        [int]$IntervalMinutes = 60,
        
        [int]$AlertThreshold = 1,
        
        [string]$LogPath
    )
    
    try {
        Write-Verbose "Starting corruption monitoring..."
        
        if (-not $DriveLetters) {
            $DriveLetters = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { 
                $_.DriveType -eq 3 -and $_.Size -gt 0 
            } | Select-Object -ExpandProperty DeviceID
        }
        
        $monitoringResults = @{
            StartTime = Get-Date
            ComputerName = $env:COMPUTERNAME
            DriveLetters = $DriveLetters
            IntervalMinutes = $IntervalMinutes
            AlertThreshold = $AlertThreshold
            LogPath = $LogPath
            MonitoringActive = $true
            ChecksPerformed = 0
            AlertsGenerated = 0
            LastCheckTime = $null
            LastCheckResults = $null
        }
        
        Write-Verbose "Corruption monitoring started for drives: $($DriveLetters -join ', ')"
        Write-Verbose "Monitoring interval: $IntervalMinutes minutes"
        Write-Verbose "Alert threshold: $AlertThreshold errors"
        
        # Start monitoring loop
        while ($monitoringResults.MonitoringActive) {
            try {
                $checkTime = Get-Date
                $monitoringResults.LastCheckTime = $checkTime
                $monitoringResults.ChecksPerformed++
                
                Write-Verbose "Performing corruption check #$($monitoringResults.ChecksPerformed)..."
                
                # Perform corruption test
                $corruptionTest = Test-DataCorruption -DriveLetters $DriveLetters -ScanOnly
                $monitoringResults.LastCheckResults = $corruptionTest
                
                # Check for alerts
                $totalErrors = $corruptionTest.Summary.TotalErrors
                if ($totalErrors -ge $AlertThreshold) {
                    $monitoringResults.AlertsGenerated++
                    
                    $alertMessage = "CORRUPTION ALERT: $totalErrors errors detected on drives: $($DriveLetters -join ', ')"
                    Write-Warning $alertMessage
                    
                    # Log alert
                    if ($LogPath) {
                        $logEntry = "[$checkTime] ALERT: $alertMessage"
                        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
                    }
                }
                
                # Log check results
                if ($LogPath) {
                    $logEntry = "[$checkTime] Check #$($monitoringResults.ChecksPerformed): $totalErrors errors detected"
                    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
                }
                
                Write-Verbose "Corruption check completed. Errors: $totalErrors"
                
                # Wait for next check
                Start-Sleep -Seconds ($IntervalMinutes * 60)
                
            } catch {
                Write-Warning "Error during corruption monitoring: $($_.Exception.Message)"
                Start-Sleep -Seconds 60  # Wait 1 minute before retrying
            }
        }
        
        return [PSCustomObject]$monitoringResults
        
    } catch {
        Write-Error "Error starting corruption monitoring: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-DataCorruption',
    'Repair-DataCorruption',
    'Get-DiskHealthReport',
    'Start-CorruptionMonitoring'
)

# Module initialization
Write-Verbose "BackupStorage-DataCorruption module loaded successfully. Version: $ModuleVersion"
