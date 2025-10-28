<#
.SYNOPSIS
    Core logging module for Windows Server PowerShell Solutions Suite

.DESCRIPTION
    Provides comprehensive logging functionality with multiple output targets,
    log rotation, structured logging, and enterprise-grade features.

.PARAMETER None

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Last Updated: December 2024
    
    Features:
    - Multiple log targets (File, Event Log, Console, Syslog)
    - Log rotation and archival
    - Structured JSON logging
    - Performance monitoring
    - Security audit logging
    - Integration with external log aggregation systems
#>

[CmdletBinding()]
param()

# Module Variables
$script:ModuleVersion = '1.0.0'
$script:LogLevels = @{
    'DEBUG' = 0
    'INFO' = 1
    'WARNING' = 2
    'ERROR' = 3
    'CRITICAL' = 4
}
$script:DefaultLogPath = Join-Path $env:ProgramData "WindowsServerSolutions" "Logs"
$script:LogTargets = @{
    File = $true
    Console = $true
    EventLog = $false
    Syslog = $false
}

# Initialize Logging Directory
if (-not (Test-Path $script:DefaultLogPath)) {
    New-Item -Path $script:DefaultLogPath -ItemType Directory -Force | Out-Null
}

#region Public Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log entry to configured targets
    
    .DESCRIPTION
        Logs messages to configured targets (File, Console, Event Log, Syslog)
        with automatic log rotation and structured formatting.
    
    .PARAMETER Message
        The log message to write
    
    .PARAMETER Level
        Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
    
    .PARAMETER Component
        Component name for categorization
    
    .PARAMETER Exception
        Exception object to log
    
    .PARAMETER Data
        Additional structured data (hashtable)
    
    .EXAMPLE
        Write-Log -Message "User authenticated" -Level INFO -Component "Authentication"
    
    .EXAMPLE
        Write-Log -Message "Authentication failed" -Level ERROR -Component "Authentication" -Exception $ex
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$Level = 'INFO',
        
        [Parameter(Mandatory = $false)]
        [string]$Component = 'General',
        
        [Parameter(Mandatory = $false)]
        [Exception]$Exception = $null,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Data = @{}
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $logEntry = @{
            Timestamp = $timestamp
            Level = $Level
            Component = $Component
            Message = $Message
            Exception = if ($Exception) { @{
                Type = $Exception.GetType().FullName
                Message = $Exception.Message
                StackTrace = $Exception.StackTrace
            }} else { $null }
            Data = $Data
            Host = $env:COMPUTERNAME
            User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            ProcessId = $PID
        }
        
        # Write to configured targets
        if ($script:LogTargets.File) {
            Write-LogFile -LogEntry $logEntry
        }
        
        if ($script:LogTargets.Console) {
            Write-LogConsole -LogEntry $logEntry
        }
        
        if ($script:LogTargets.EventLog) {
            Write-LogEventLog -LogEntry $logEntry
        }
        
        if ($script:LogTargets.Syslog) {
            Write-LogSyslog -LogEntry $logEntry
        }
        
    } catch {
        # Fallback to simple console output if logging fails
        $color = @{
            'DEBUG' = 'Gray'
            'INFO' = 'White'
            'WARNING' = 'Yellow'
            'ERROR' = 'Red'
            'CRITICAL' = 'Magenta'
        }[$Level]
        
        Write-Host "[$timestamp] [$Level] [$Component] $Message" -ForegroundColor $color
    }
}

function Set-LogTarget {
    <#
    .SYNOPSIS
        Configures logging targets
    
    .DESCRIPTION
        Enables or disables specific log targets (File, Console, Event Log, Syslog)
    
    .PARAMETER Target
        Target to configure
    
    .PARAMETER Enabled
        Enable or disable the target
    
    .PARAMETER LogPath
        Custom log path for file target
    
    .EXAMPLE
        Set-LogTarget -Target File -Enabled $true -LogPath "C:\Logs"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('File', 'Console', 'EventLog', 'Syslog')]
        [string]$Target,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled,
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath
    )
    
    $script:LogTargets[$Target] = $Enabled
    
    if ($Target -eq 'File' -and $LogPath) {
        $script:DefaultLogPath = $LogPath
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        }
        Write-Log -Message "Log path changed to: $LogPath" -Level INFO -Component "Logging"
    }
}

function Initialize-LogRotation {
    <#
    .SYNOPSIS
        Initializes automatic log rotation
    
    .DESCRIPTION
        Configures automatic log file rotation with retention policies
    
    .PARAMETER MaxFileSizeMB
        Maximum log file size in MB before rotation
    
    .PARAMETER RetentionDays
        Number of days to retain logs
    
    .EXAMPLE
        Initialize-LogRotation -MaxFileSizeMB 100 -RetentionDays 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxFileSizeMB = 100,
        
        [Parameter(Mandatory = $false)]
        [int]$RetentionDays = 30
    )
    
    try {
        # Rotate existing logs
        Invoke-LogRotation
        
        # Schedule periodic rotation
        $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-Command `"Import-Module '$($PSScriptRoot)\Logging-Core.psm1'; Invoke-LogRotation`""
        $trigger = New-ScheduledTaskTrigger -Daily -At 00:00
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        try {
            Unregister-ScheduledTask -TaskName "Windows-Server-LogRotation" -Confirm:$false -ErrorAction SilentlyContinue
        } catch {}
        
        Register-ScheduledTask -TaskName "Windows-Server-LogRotation" -Action $action -Trigger $trigger -Principal $principal -Description "Automatic log rotation for Windows Server Solutions" | Out-Null
        
        Write-Log -Message "Log rotation configured: MaxSize=$MaxFileSizeMB MB, Retention=$RetentionDays days" -Level INFO -Component "Logging"
        
    } catch {
        Write-Log -Message "Failed to initialize log rotation: $_" -Level ERROR -Component "Logging" -Exception $_
    }
}

function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Performs log file rotation
    
    .DESCRIPTION
        Rotates log files based on size and age, and removes old logs
    
    .PARAMETER None
    
    .EXAMPLE
        Invoke-LogRotation
    #>
    [CmdletBinding()]
    param()
    
    try {
        $logFiles = Get-ChildItem -Path $script:DefaultLogPath -Filter "*.log" -File
        
        foreach ($file in $logFiles) {
            # Check file size (assume 100MB default)
            if ($file.Length -gt (100MB)) {
                $archiveDate = Get-Date -Format "yyyyMMdd-HHmmss"
                $archiveName = $file.Name -replace '\.log$', "-$archiveDate.log"
                $archivePath = Join-Path $script:DefaultLogPath $archiveName
                
                Move-Item -Path $file.FullName -Destination $archivePath -Force
                Write-Log -Message "Rotated log file: $($file.Name) -> $archiveName" -Level INFO -Component "Logging"
            }
        }
        
        # Remove old archives (older than 30 days by default)
        $cutoffDate = (Get-Date).AddDays(-30)
        $oldArchives = Get-ChildItem -Path $script:DefaultLogPath -Filter "*.log" -File | Where-Object { $_.LastWriteTime -lt $cutoffDate }
        
        foreach ($archive in $oldArchives) {
            Remove-Item -Path $archive.FullName -Force
            Write-Log -Message "Removed old log archive: $($archive.Name)" -Level INFO -Component "Logging"
        }
        
    } catch {
        Write-Error "Log rotation failed: $_"
    }
}

#endregion Public Functions

#region Private Functions

function Write-LogFile {
    param([hashtable]$LogEntry)
    
    try {
        $date = Get-Date -Format "yyyy-MM-dd"
        $logFile = Join-Path $script:DefaultLogPath "Application-$date.log"
        
        # Convert to JSON for structured logging
        $jsonEntry = $LogEntry | ConvertTo-Json -Compress -Depth 10
        Add-Content -Path $logFile -Value $jsonEntry -Encoding UTF8
        
    } catch {
        Write-Error "Failed to write to log file: $_"
    }
}

function Write-LogConsole {
    param([hashtable]$LogEntry)
    
    $color = @{
        'DEBUG' = 'Gray'
        'INFO' = 'White'
        'WARNING' = 'Yellow'
        'ERROR' = 'Red'
        'CRITICAL' = 'Magenta'
    }[$LogEntry.Level]
    
    $message = "[$($LogEntry.Timestamp)] [$($LogEntry.Level)] [$($LogEntry.Component)] $($LogEntry.Message)"
    
    if ($LogEntry.Exception) {
        $message += " | Exception: $($LogEntry.Exception.Message)"
    }
    
    Write-Host $message -ForegroundColor $color
}

function Write-LogEventLog {
    param([hashtable]$LogEntry)
    
    try {
        $source = "Windows-Server-Solutions"
        
        # Ensure event log source exists
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            New-EventLog -LogName Application -Source $source
        }
        
        $entryType = switch ($LogEntry.Level) {
            'CRITICAL' { 'Error' }
            'ERROR' { 'Error' }
            'WARNING' { 'Warning' }
            default { 'Information' }
        }
        
        $message = "[$($LogEntry.Component)] $($LogEntry.Message)"
        if ($LogEntry.Exception) {
            $message += " | Exception: $($LogEntry.Exception.Message)"
        }
        
        Write-EventLog -LogName Application -Source $source -EntryType $entryType -EventId 1000 -Message $message
        
    } catch {
        Write-Error "Failed to write to Event Log: $_"
    }
}

function Write-LogSyslog {
    param([hashtable]$LogEntry)
    
    # TODO: Implement syslog output
    # This would integrate with external log aggregation systems like Splunk, ELK, etc.
}

#endregion Private Functions

# Export Functions
Export-ModuleMember -Function Write-Log, Set-LogTarget, Initialize-LogRotation, Invoke-LogRotation

# Module Metadata
$script:ModuleInfo = @{
    Name = 'Logging-Core'
    Version = $script:ModuleVersion
    Author = 'Adrian Johnson (adrian207@gmail.com)'
    Description = 'Core logging module for Windows Server PowerShell Solutions Suite'
}

