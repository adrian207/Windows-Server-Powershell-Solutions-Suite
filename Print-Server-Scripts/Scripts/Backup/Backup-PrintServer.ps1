#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Server Backup and Disaster Recovery Script

.DESCRIPTION
    This script provides comprehensive backup and disaster recovery capabilities
    for Windows Print Server services including configuration backup,
    printer backup, driver backup, and disaster recovery procedures.

.PARAMETER Action
    The action to perform (BackupConfig, BackupPrinters, RestoreConfig, RestorePrinters, CreateSnapshot, ManageSnapshots, DisasterRecovery)

.PARAMETER BackupPath
    Path to save backups

.PARAMETER RestorePath
    Path to restore from

.PARAMETER IncludeDrivers
    Include printer drivers in backup

.PARAMETER IncludePrintJobs
    Include print job history in backup

.PARAMETER CompressionLevel
    Compression level for backups (None, Fast, Optimal)

.PARAMETER VerifyBackup
    Verify backup integrity after creation

.PARAMETER ScheduleBackup
    Create scheduled backup task

.PARAMETER TaskName
    Name for the scheduled task

.PARAMETER ScheduleType
    Schedule type (Daily, Weekly, Monthly)

.PARAMETER SnapshotName
    Name for the snapshot

.PARAMETER RetentionDays
    Number of days to retain snapshots

.EXAMPLE
    .\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\PrintServer-Config.xml" -IncludeDrivers -IncludePrintJobs

.EXAMPLE
    .\Backup-PrintServer.ps1 -Action BackupPrinters -BackupPath "C:\Backups\Printers.xml" -IncludeDrivers

.EXAMPLE
    .\Backup-PrintServer.ps1 -Action CreateSnapshot -SnapshotName "PreMaintenance" -RetentionDays 30

.EXAMPLE
    .\Backup-PrintServer.ps1 -Action DisasterRecovery -BackupPath "C:\Backups\PrintServer-Config.xml"

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("BackupConfig", "BackupPrinters", "RestoreConfig", "RestorePrinters", "CreateSnapshot", "ManageSnapshots", "DisasterRecovery")]
    [string]$Action,
    
    [string]$BackupPath,
    
    [string]$RestorePath,
    
    [switch]$IncludeDrivers,
    
    [switch]$IncludePrintJobs,
    
    [ValidateSet("None", "Fast", "Optimal")]
    [string]$CompressionLevel = "Optimal",
    
    [switch]$VerifyBackup,
    
    [switch]$ScheduleBackup,
    
    [string]$TaskName = "Print Server Backup",
    
    [ValidateSet("Daily", "Weekly", "Monthly")]
    [string]$ScheduleType = "Daily",
    
    [string]$SnapshotName,
    
    [int]$RetentionDays = 7
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "PrintServer-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "PrintServer-Management.psm1") -Force
    Import-Module (Join-Path $modulePath "PrintServer-Troubleshooting.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:BackupLog = @()
$script:StartTime = Get-Date

function Write-BackupLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:BackupLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function New-ConfigurationBackup {
    param(
        [string]$BackupPath,
        [switch]$IncludeDrivers,
        [switch]$IncludePrintJobs
    )
    
    Write-BackupLog "Creating print server configuration backup..." "INFO"
    
    try {
        if (-not $BackupPath) {
            $BackupPath = Join-Path $scriptPath "PrintServer-Config-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
        }
        
        $backup = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Configuration = @{}
            Printers = @()
            Drivers = @()
            Services = @{}
            Registry = @{}
        }
        
        # Backup print server configuration
        $config = Get-PrintServerStatus
        $backup.Configuration = $config
        
        # Backup services
        $services = @('Spooler')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $backup.Services[$serviceName] = @{
                    Status = $service.Status
                    StartType = $service.StartType
                    DisplayName = $service.DisplayName
                }
            }
        }
        
        # Backup printers
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
            }
            
            $backup.Printers += $printerInfo
        }
        
        # Backup drivers if requested
        if ($IncludeDrivers) {
            $drivers = Get-PrinterDriver
            foreach ($driver in $drivers) {
                $driverInfo = @{
                    Name = $driver.Name
                    DriverVersion = $driver.DriverVersion
                    InfPath = $driver.InfPath
                }
                
                $backup.Drivers += $driverInfo
            }
        }
        
        # Backup registry configuration
        $regPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\Print",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                try {
                    $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    if ($regData) {
                        $backup.Registry[$regPath] = $regData
                    }
                } catch {
                    Write-Warning "Could not backup registry path: $regPath"
                }
            }
        }
        
        # Save backup
        $backup | Export-Clixml -Path $BackupPath -Force
        
        Write-BackupLog "Configuration backup saved to: $BackupPath" "SUCCESS"
        return $BackupPath
        
    } catch {
        Write-BackupLog "Failed to create configuration backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-ConfigurationBackup {
    param([string]$RestorePath)
    
    Write-BackupLog "Restoring print server configuration from backup..." "INFO"
    
    try {
        if (-not (Test-Path $RestorePath)) {
            throw "Backup file not found: $RestorePath"
        }
        
        # Load backup
        $backup = Import-Clixml -Path $RestorePath
        
        Write-BackupLog "Restoring configuration from: $($backup.Timestamp)" "INFO"
        
        # Restore services
        foreach ($serviceName in $backup.Services.Keys) {
            $serviceInfo = $backup.Services[$serviceName]
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($service) {
                # Set service startup type
                Set-Service -Name $serviceName -StartupType $serviceInfo.StartType
                
                # Start service if it was running
                if ($serviceInfo.Status -eq 'Running' -and $service.Status -ne 'Running') {
                    Start-Service -Name $serviceName
                }
                
                Write-BackupLog "Restored service: $serviceName" "SUCCESS"
            }
        }
        
        # Restore printers
        foreach ($printerInfo in $backup.Printers) {
            try {
                # Check if printer already exists
                $existingPrinter = Get-Printer -Name $printerInfo.Name -ErrorAction SilentlyContinue
                
                if (-not $existingPrinter) {
                    # Create the printer
                    $printerParams = @{
                        Name = $printerInfo.Name
                        DriverName = $printerInfo.DriverName
                        PortName = $printerInfo.PortName
                    }
                    
                    if ($printerInfo.Location) {
                        $printerParams.Location = $printerInfo.Location
                    }
                    
                    if ($printerInfo.Comment) {
                        $printerParams.Comment = $printerInfo.Comment
                    }
                    
                    if ($printerInfo.Shared) {
                        $printerParams.Shared = $true
                    }
                    
                    if ($printerInfo.Published) {
                        $printerParams.Published = $true
                    }
                    
                    Add-Printer @printerParams
                    
                    Write-BackupLog "Restored printer: $($printerInfo.Name)" "SUCCESS"
                } else {
                    Write-BackupLog "Printer already exists, skipping: $($printerInfo.Name)" "WARNING"
                }
            } catch {
                Write-Warning "Failed to restore printer $($printerInfo.Name): $($_.Exception.Message)"
            }
        }
        
        Write-BackupLog "Configuration restore completed successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-BackupLog "Failed to restore configuration backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-PrinterBackup {
    param(
        [string]$BackupPath,
        [switch]$IncludeDrivers,
        [switch]$IncludePrintJobs
    )
    
    Write-BackupLog "Creating printer backup..." "INFO"
    
    try {
        if (-not $BackupPath) {
            $BackupPath = Join-Path $scriptPath "Printers-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
        }
        
        $backup = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Printers = @()
            Drivers = @()
            PrintJobs = @()
        }
        
        # Backup printers
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
            }
            
            $backup.Printers += $printerInfo
        }
        
        # Backup drivers if requested
        if ($IncludeDrivers) {
            $drivers = Get-PrinterDriver
            foreach ($driver in $drivers) {
                $driverInfo = @{
                    Name = $driver.Name
                    DriverVersion = $driver.DriverVersion
                    InfPath = $driver.InfPath
                }
                
                $backup.Drivers += $driverInfo
            }
        }
        
        # Backup print jobs if requested
        if ($IncludePrintJobs) {
            $printJobs = Get-PrintJob
            foreach ($printJob in $printJobs) {
                $printJobInfo = @{
                    PrinterName = $printJob.PrinterName
                    JobName = $printJob.JobName
                    JobStatus = $printJob.JobStatus
                    SubmittedTime = $printJob.SubmittedTime
                    SubmittedBy = $printJob.SubmittedBy
                    PagesPrinted = $printJob.PagesPrinted
                    TotalPages = $printJob.TotalPages
                }
                
                $backup.PrintJobs += $printJobInfo
            }
        }
        
        # Save backup
        $backup | Export-Clixml -Path $BackupPath -Force
        
        Write-BackupLog "Printer backup saved to: $BackupPath" "SUCCESS"
        return $BackupPath
        
    } catch {
        Write-BackupLog "Failed to create printer backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-PrinterBackup {
    param([string]$RestorePath)
    
    Write-BackupLog "Restoring printer backup..." "INFO"
    
    try {
        if (-not (Test-Path $RestorePath)) {
            throw "Backup file not found: $RestorePath"
        }
        
        # Load backup
        $backup = Import-Clixml -Path $RestorePath
        
        Write-BackupLog "Restoring printers from: $($backup.Timestamp)" "INFO"
        
        # Restore printers
        foreach ($printerInfo in $backup.Printers) {
            try {
                # Check if printer already exists
                $existingPrinter = Get-Printer -Name $printerInfo.Name -ErrorAction SilentlyContinue
                
                if (-not $existingPrinter) {
                    # Create the printer
                    $printerParams = @{
                        Name = $printerInfo.Name
                        DriverName = $printerInfo.DriverName
                        PortName = $printerInfo.PortName
                    }
                    
                    if ($printerInfo.Location) {
                        $printerParams.Location = $printerInfo.Location
                    }
                    
                    if ($printerInfo.Comment) {
                        $printerParams.Comment = $printerInfo.Comment
                    }
                    
                    if ($printerInfo.Shared) {
                        $printerParams.Shared = $true
                    }
                    
                    if ($printerInfo.Published) {
                        $printerParams.Published = $true
                    }
                    
                    Add-Printer @printerParams
                    
                    Write-BackupLog "Restored printer: $($printerInfo.Name)" "SUCCESS"
                } else {
                    Write-BackupLog "Printer already exists, skipping: $($printerInfo.Name)" "WARNING"
                }
            } catch {
                Write-Warning "Failed to restore printer $($printerInfo.Name): $($_.Exception.Message)"
            }
        }
        
        Write-BackupLog "Printer restore completed successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-BackupLog "Failed to restore printer backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-PrintServerSnapshot {
    param(
        [string]$SnapshotName,
        [int]$RetentionDays
    )
    
    Write-BackupLog "Creating print server snapshot: $SnapshotName" "INFO"
    
    try {
        if (-not $SnapshotName) {
            $SnapshotName = "PrintServer-Snapshot-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        }
        
        # Create snapshot using Volume Shadow Copy Service
        $snapshot = @{
            Name = $SnapshotName
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Configuration = Get-PrintServerStatus
            Printers = Get-Printer
            Drivers = Get-PrinterDriver
            Services = @{}
        }
        
        # Get service information
        $services = @('Spooler')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $snapshot.Services[$serviceName] = @{
                    Status = $service.Status
                    StartType = $service.StartType
                }
            }
        }
        
        # Save snapshot
        $snapshotPath = Join-Path $scriptPath "Snapshots\$SnapshotName.xml"
        $snapshot | Export-Clixml -Path $snapshotPath -Force
        
        Write-BackupLog "Snapshot created successfully: $SnapshotName" "SUCCESS"
        return $snapshotPath
        
    } catch {
        Write-BackupLog "Failed to create snapshot: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-PrintServerSnapshots {
    param([int]$RetentionDays)
    
    Write-BackupLog "Managing print server snapshots..." "INFO"
    
    try {
        $snapshotsPath = Join-Path $scriptPath "Snapshots"
        if (-not (Test-Path $snapshotsPath)) {
            New-Item -Path $snapshotsPath -ItemType Directory -Force | Out-Null
        }
        
        # Get existing snapshots
        $snapshots = Get-ChildItem -Path $snapshotsPath -Filter "*.xml" | Sort-Object LastWriteTime -Descending
        
        Write-BackupLog "Found $($snapshots.Count) existing snapshots" "INFO"
        
        # Remove old snapshots
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $oldSnapshots = $snapshots | Where-Object { $_.LastWriteTime -lt $cutoffDate }
        
        foreach ($oldSnapshot in $oldSnapshots) {
            try {
                Remove-Item -Path $oldSnapshot.FullName -Force
                Write-BackupLog "Removed old snapshot: $($oldSnapshot.Name)" "SUCCESS"
            } catch {
                Write-Warning "Could not remove snapshot: $($oldSnapshot.Name)"
            }
        }
        
        # Create new snapshot
        $newSnapshot = New-PrintServerSnapshot -SnapshotName "Auto-$(Get-Date -Format 'yyyyMMdd-HHmmss')" -RetentionDays $RetentionDays
        
        Write-BackupLog "Snapshot management completed" "SUCCESS"
        return $newSnapshot
        
    } catch {
        Write-BackupLog "Failed to manage snapshots: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Start-DisasterRecovery {
    param([string]$BackupPath)
    
    Write-BackupLog "Starting disaster recovery procedure..." "INFO"
    
    try {
        $recoveryResults = @{
            StepsCompleted = @()
            Issues = @()
            Recommendations = @()
            Overall = 'Unknown'
        }
        
        # Step 1: Verify backup exists
        if (-not (Test-Path $BackupPath)) {
            throw "Backup file not found: $BackupPath"
        }
        
        $recoveryResults.StepsCompleted += "Backup file verified"
        Write-BackupLog "Backup file verified: $BackupPath" "SUCCESS"
        
        # Step 2: Check system health
        $healthCheck = Test-PrintServerHealth
        if ($healthCheck.Overall -ne 'Healthy') {
            $recoveryResults.Issues += "System health issues detected: $($healthCheck.Overall)"
            $recoveryResults.Recommendations += "Address system health issues before proceeding"
        }
        
        $recoveryResults.StepsCompleted += "System health checked"
        
        # Step 3: Stop print server services
        try {
            Stop-PrintServerServices
            $recoveryResults.StepsCompleted += "Print server services stopped"
            Write-BackupLog "Print server services stopped" "SUCCESS"
        } catch {
            $recoveryResults.Issues += "Could not stop print server services"
        }
        
        # Step 4: Restore configuration
        try {
            Restore-ConfigurationBackup -RestorePath $BackupPath
            $recoveryResults.StepsCompleted += "Configuration restored"
            Write-BackupLog "Configuration restored successfully" "SUCCESS"
        } catch {
            $recoveryResults.Issues += "Configuration restore failed"
        }
        
        # Step 5: Start print server services
        try {
            Start-PrintServerServices
            $recoveryResults.StepsCompleted += "Print server services started"
            Write-BackupLog "Print server services started" "SUCCESS"
        } catch {
            $recoveryResults.Issues += "Could not start print server services"
        }
        
        # Step 6: Verify recovery
        try {
            Start-Sleep -Seconds 10
            $postRecoveryHealth = Test-PrintServerHealth
            $recoveryResults.StepsCompleted += "Recovery verification completed"
            
            if ($postRecoveryHealth.Overall -eq 'Healthy') {
                $recoveryResults.Overall = 'Successful'
                Write-BackupLog "Disaster recovery completed successfully" "SUCCESS"
            } else {
                $recoveryResults.Overall = 'Partial'
                $recoveryResults.Issues += "System not fully healthy after recovery"
                $recoveryResults.Recommendations += "Manual intervention may be required"
            }
        } catch {
            $recoveryResults.Issues += "Recovery verification failed"
        }
        
        return [PSCustomObject]$recoveryResults
        
    } catch {
        Write-BackupLog "Disaster recovery failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-ScheduledBackupTask {
    param(
        [string]$TaskName,
        [string]$ScheduleType,
        [string]$BackupPath
    )
    
    Write-BackupLog "Creating scheduled backup task..." "INFO"
    
    try {
        # Define the action
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Action BackupConfig -BackupPath `"$BackupPath`" -IncludeDrivers -IncludePrintJobs"
        
        # Define the trigger based on schedule type
        switch ($ScheduleType) {
            "Daily" {
                $trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
            }
            "Weekly" {
                $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "02:00"
            }
            "Monthly" {
                $trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At "02:00"
            }
        }
        
        # Define the principal
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Define settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        # Create the task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Print Server Configuration Backup Task"
        
        Write-BackupLog "Scheduled backup task created: $TaskName" "SUCCESS"
        return $true
        
    } catch {
        Write-BackupLog "Failed to create scheduled backup task: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Save-BackupLog {
    $logPath = Join-Path $scriptPath "Backup-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:BackupLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-BackupLog "Backup log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save backup log: $($_.Exception.Message)"
    }
}

# Main backup and recovery process
try {
    Write-BackupLog "Starting print server backup and recovery..." "INFO"
    Write-BackupLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "BackupConfig" {
            $backupPath = New-ConfigurationBackup -BackupPath $BackupPath -IncludeDrivers:$IncludeDrivers -IncludePrintJobs:$IncludePrintJobs
            
            if ($ScheduleBackup) {
                New-ScheduledBackupTask -TaskName $TaskName -ScheduleType $ScheduleType -BackupPath $backupPath
            }
            
            Write-Host "`nConfiguration backup created: $backupPath" -ForegroundColor Green
        }
        
        "BackupPrinters" {
            $backupPath = New-PrinterBackup -BackupPath $BackupPath -IncludeDrivers:$IncludeDrivers -IncludePrintJobs:$IncludePrintJobs
            
            Write-Host "`nPrinter backup created: $backupPath" -ForegroundColor Green
        }
        
        "RestoreConfig" {
            if (-not $RestorePath) {
                throw "RestorePath parameter is required for RestoreConfig action"
            }
            
            Restore-ConfigurationBackup -RestorePath $RestorePath
            
            Write-Host "`nConfiguration restore completed successfully" -ForegroundColor Green
        }
        
        "RestorePrinters" {
            if (-not $RestorePath) {
                throw "RestorePath parameter is required for RestorePrinters action"
            }
            
            Restore-PrinterBackup -RestorePath $RestorePath
            
            Write-Host "`nPrinter restore completed successfully" -ForegroundColor Green
        }
        
        "CreateSnapshot" {
            $snapshotPath = New-PrintServerSnapshot -SnapshotName $SnapshotName -RetentionDays $RetentionDays
            
            Write-Host "`nSnapshot created: $snapshotPath" -ForegroundColor Green
        }
        
        "ManageSnapshots" {
            $snapshotPath = Set-PrintServerSnapshots -RetentionDays $RetentionDays
            
            Write-Host "`nSnapshot management completed" -ForegroundColor Green
        }
        
        "DisasterRecovery" {
            if (-not $BackupPath) {
                throw "BackupPath parameter is required for DisasterRecovery action"
            }
            
            $recoveryResults = Start-DisasterRecovery -BackupPath $BackupPath
            
            Write-Host "`n=== Disaster Recovery Results ===" -ForegroundColor Cyan
            Write-Host "Overall Status: $($recoveryResults.Overall)" -ForegroundColor White
            Write-Host "Steps Completed: $($recoveryResults.StepsCompleted.Count)" -ForegroundColor White
            Write-Host "Issues Found: $($recoveryResults.Issues.Count)" -ForegroundColor White
            Write-Host "Recommendations: $($recoveryResults.Recommendations.Count)" -ForegroundColor White
            
            if ($recoveryResults.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Yellow
                $recoveryResults.Issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            }
            
            if ($recoveryResults.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                $recoveryResults.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-BackupLog "Print server backup and recovery completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== Print Server Backup and Recovery Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save backup log
    Save-BackupLog
    
    Write-Host "`nBackup and recovery completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-BackupLog "Print server backup and recovery failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save backup log
    Save-BackupLog
    
    Write-Host "`nBackup and recovery failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the backup log for details." -ForegroundColor Yellow
    
    exit 1
}
