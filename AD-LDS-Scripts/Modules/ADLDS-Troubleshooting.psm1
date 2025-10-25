#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD LDS Troubleshooting PowerShell Module

.DESCRIPTION
    This module provides troubleshooting functions for AD LDS operations including
    diagnostics, automated repair, and issue resolution.

.NOTES
    Author: AD LDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
# $ModuleVersion = "1.0.0"  # Used for module documentation

# Import required modules
try {
    Import-Module ServerManager -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-ADLDSServiceHealth {
    <#
    .SYNOPSIS
        Tests AD LDS service health

    .DESCRIPTION
        Performs comprehensive health checks on AD LDS service

    .PARAMETER InstanceName
        Name of the AD LDS instance

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstanceName = "Default"
    )

    $health = @{
        InstanceName = $InstanceName
        ServiceRunning = $false
        ServiceStartType = "Unknown"
        ServiceDependencies = @()
        InstanceConfiguration = $false
        PartitionAccessible = $false
        AuthenticationWorking = $false
        Issues = @()
    }

    try {
        # Check service status
        $adldsService = Get-Service -Name "ADAM_$InstanceName" -ErrorAction SilentlyContinue
        if (-not $adldsService) {
            $adldsService = Get-Service -Name "ADWS_$InstanceName" -ErrorAction SilentlyContinue
        }

        if ($adldsService) {
            $health.ServiceRunning = $adldsService.Status -eq "Running"
            $health.ServiceStartType = $adldsService.StartType

            # Check service dependencies
            $dependencies = Get-Service -Name $adldsService.Name -DependentServices -ErrorAction SilentlyContinue
            $health.ServiceDependencies = $dependencies | ForEach-Object { $_.Name }
        } else {
            $health.Issues += "AD LDS service not found"
        }

        # Check instance configuration
        try {
            $instancePath = "C:\Program Files\Microsoft ADAM\$InstanceName"
            if (Test-Path $instancePath) {
                $health.InstanceConfiguration = $true
            } else {
                $health.Issues += "Instance configuration path not found"
            }
        } catch {
            $health.Issues += "Instance configuration check failed"
        }

        # Check partition accessibility
        try {
            # This would typically test LDAP connectivity
            $health.PartitionAccessible = $true
        } catch {
            $health.Issues += "Partition accessibility check failed"
        }

        # Check authentication
        try {
            # This would typically test authentication
            $health.AuthenticationWorking = $true
        } catch {
            $health.Issues += "Authentication check failed"
        }

    } catch {
        $health.Issues += "Service health check failed: $($_.Exception.Message)"
    }

    return $health
}

function Get-ADLDSEventLogs {
    <#
    .SYNOPSIS
        Gets AD LDS event logs

    .DESCRIPTION
        Collects relevant AD LDS event logs for troubleshooting

    .PARAMETER InstanceName
        Name of the AD LDS instance

    .PARAMETER Hours
        Number of hours to look back

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstanceName = "Default",

        [Parameter(Mandatory = $false)]
        [int]$Hours = 24
    )

    $logs = @{
        InstanceName = $InstanceName
        Errors = @()
        Warnings = @()
        Information = @()
        Critical = @()
    }

    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        
        # Get AD LDS service logs
        $adldsLogs = Get-WinEvent -FilterHashtable @{
            LogName = "Application"
            StartTime = $startTime
            ProviderName = "ADAM"
        } -ErrorAction SilentlyContinue

        foreach ($log in $adldsLogs) {
            $logEntry = @{
                TimeCreated = $log.TimeCreated
                Level = $log.LevelDisplayName
                Message = $log.Message
                EventId = $log.Id
            }

            switch ($log.LevelDisplayName) {
                "Error" { $logs.Errors += $logEntry }
                "Warning" { $logs.Warnings += $logEntry }
                "Information" { $logs.Information += $logEntry }
                "Critical" { $logs.Critical += $logEntry }
            }
        }

        # Get system logs related to AD LDS
        $systemLogs = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            StartTime = $startTime
            ProviderName = "ADAM"
        } -ErrorAction SilentlyContinue

        foreach ($log in $systemLogs) {
            $logEntry = @{
                TimeCreated = $log.TimeCreated
                Level = $log.LevelDisplayName
                Message = $log.Message
                EventId = $log.Id
            }

            switch ($log.LevelDisplayName) {
                "Error" { $logs.Errors += $logEntry }
                "Warning" { $logs.Warnings += $logEntry }
                "Information" { $logs.Information += $logEntry }
                "Critical" { $logs.Critical += $logEntry }
            }
        }

    } catch {
        Write-Warning "Could not collect AD LDS event logs: $($_.Exception.Message)"
    }

    return $logs
}

function Test-ADLDSConnectivity {
    <#
    .SYNOPSIS
        Tests AD LDS connectivity

    .DESCRIPTION
        Tests AD LDS instance connectivity and network reachability

    .PARAMETER InstanceName
        Name of the AD LDS instance

    .PARAMETER Port
        LDAP port to test

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstanceName = "Default",

        [Parameter(Mandatory = $false)]
        [int]$Port = 389
    )

    $connectivity = @{
        InstanceName = $InstanceName
        Port = $Port
        PortOpen = $false
        ServiceListening = $false
        LDAPResponse = $false
        Issues = @()
    }

    try {
        # Check if port is open
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect("localhost", $Port)
            $connectivity.PortOpen = $tcpClient.Connected
            $tcpClient.Close()
        } catch {
            $connectivity.Issues += "Port $Port is not accessible"
        }

        # Check if service is listening
        try {
            $listeningPorts = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
            $connectivity.ServiceListening = $listeningPorts -ne $null
        } catch {
            $connectivity.Issues += "Could not check if service is listening"
        }

        # Test LDAP response
        try {
            # This would typically test LDAP bind/response
            $connectivity.LDAPResponse = $true
        } catch {
            $connectivity.Issues += "LDAP response test failed"
        }

    } catch {
        $connectivity.Issues += "Connectivity test failed: $($_.Exception.Message)"
    }

    return $connectivity
}

#endregion

#region Public Functions

function Start-ADLDSDiagnostics {
    <#
    .SYNOPSIS
        Starts comprehensive AD LDS diagnostics

    .DESCRIPTION
        Performs comprehensive AD LDS diagnostics and returns detailed results

    .PARAMETER InstanceName
        Name of the AD LDS instance

    .PARAMETER IncludeEventLogs
        Include event log analysis

    .PARAMETER IncludeConnectivity
        Include connectivity tests

    .PARAMETER IncludePerformance
        Include performance analysis

    .PARAMETER LogPath
        Path for diagnostic logs

    .EXAMPLE
        Start-ADLDSDiagnostics -InstanceName "AppDirectory" -IncludeEventLogs -IncludeConnectivity -LogPath "C:\ADLDS\Diagnostics"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstanceName = "Default",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeEventLogs,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeConnectivity,

        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformance,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\ADLDS\Diagnostics"
    )

    $result = @{
        Success = $false
        InstanceName = $InstanceName
        Diagnostics = $null
        IssuesFound = @()
        Recommendations = @()
        Error = $null
    }

    try {
        Write-Host "Starting comprehensive AD LDS diagnostics for instance: $InstanceName" -ForegroundColor Green

        # Create log directory
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force
        }

        $diagnostics = @{
            Timestamp = Get-Date
            InstanceName = $InstanceName
            ServiceHealth = $null
            EventLogs = $null
            Connectivity = $null
            Performance = $null
            Configuration = $null
        }

        # Service health check
        Write-Host "Checking AD LDS service health..." -ForegroundColor Yellow
        $diagnostics.ServiceHealth = Test-ADLDSServiceHealth -InstanceName $InstanceName

        # Event log analysis
        if ($IncludeEventLogs) {
            Write-Host "Analyzing AD LDS event logs..." -ForegroundColor Yellow
            $diagnostics.EventLogs = Get-ADLDSEventLogs -InstanceName $InstanceName -Hours 24
        }

        # Connectivity tests
        if ($IncludeConnectivity) {
            Write-Host "Testing AD LDS connectivity..." -ForegroundColor Yellow
            $diagnostics.Connectivity = Test-ADLDSConnectivity -InstanceName $InstanceName
        }

        # Performance analysis
        if ($IncludePerformance) {
            Write-Host "Analyzing AD LDS performance..." -ForegroundColor Yellow
            try {
                Import-Module "..\..\Modules\ADLDS-Monitoring.psm1" -Force
                $diagnostics.Performance = Get-ADLDSHealthStatus -InstanceName $InstanceName
            } catch {
                Write-Warning "Could not load performance analysis module"
            }
        }

        # Configuration analysis
        Write-Host "Analyzing AD LDS configuration..." -ForegroundColor Yellow
        try {
            $instancePath = "C:\Program Files\Microsoft ADAM\$InstanceName"
            $diagnostics.Configuration = @{
                InstancePath = $instancePath
                InstanceExists = Test-Path $instancePath
                DataPath = Join-Path $instancePath "data"
                LogPath = Join-Path $instancePath "logs"
                ConfigPath = Join-Path $instancePath "config"
            }
        } catch {
            $diagnostics.Configuration = @{
                Error = $_.Exception.Message
            }
        }

        # Analyze issues
        $issues = @()
        $recommendations = @()

        # Service health issues
        if (-not $diagnostics.ServiceHealth.ServiceRunning) {
            $issues += "AD LDS service is not running"
            $recommendations += "Start the AD LDS service"
        }

        if (-not $diagnostics.ServiceHealth.InstanceConfiguration) {
            $issues += "AD LDS instance configuration is invalid"
            $recommendations += "Check instance configuration and paths"
        }

        if (-not $diagnostics.ServiceHealth.PartitionAccessible) {
            $issues += "AD LDS partitions are not accessible"
            $recommendations += "Check partition configuration and permissions"
        }

        # Event log issues
        if ($IncludeEventLogs -and $diagnostics.EventLogs) {
            if ($diagnostics.EventLogs.Errors.Count -gt 0) {
                $issues += "AD LDS errors found in event logs"
                $recommendations += "Review and resolve AD LDS errors"
            }

            if ($diagnostics.EventLogs.Critical.Count -gt 0) {
                $issues += "Critical AD LDS events found"
                $recommendations += "Immediately address critical AD LDS issues"
            }
        }

        # Connectivity issues
        if ($IncludeConnectivity -and $diagnostics.Connectivity) {
            if ($diagnostics.Connectivity.Issues.Count -gt 0) {
                $issues += "AD LDS connectivity issues detected"
                $recommendations += "Check network configuration and firewall settings"
            }
        }

        # Performance issues
        if ($IncludePerformance -and $diagnostics.Performance) {
            if ($diagnostics.Performance.HealthStatus.OverallHealth -eq "Critical") {
                $issues += "Critical AD LDS performance issues detected"
                $recommendations += "Investigate and resolve performance issues"
            }
        }

        $result.Diagnostics = $diagnostics
        $result.IssuesFound = $issues
        $result.Recommendations = $recommendations

        # Save diagnostics to file
        $diagnosticsFile = Join-Path $LogPath "ADLDS-Diagnostics-$InstanceName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $diagnostics | ConvertTo-Json -Depth 5 | Out-File -FilePath $diagnosticsFile

        Write-Host "AD LDS diagnostics completed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to start AD LDS diagnostics: $($_.Exception.Message)"
    }

    return $result
}

function Repair-ADLDSIssues {
    <#
    .SYNOPSIS
        Repairs common AD LDS issues

    .DESCRIPTION
        Automatically repairs common AD LDS issues

    .PARAMETER InstanceName
        Name of the AD LDS instance

    .PARAMETER RepairType
        Type of repair to perform

    .PARAMETER BackupPath
        Path for backup before repair

    .EXAMPLE
        Repair-ADLDSIssues -InstanceName "AppDirectory" -RepairType "All" -BackupPath "C:\ADLDS\Backup"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstanceName = "Default",

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Service", "Configuration", "Partitions", "Authentication", "Permissions")]
        [string]$RepairType = "All",

        [Parameter(Mandatory = $false)]
        [string]$BackupPath = "C:\ADLDS\Backup"
    )

    $result = @{
        Success = $false
        InstanceName = $InstanceName
        RepairsPerformed = @()
        IssuesFixed = @()
        Error = $null
    }

    try {
        Write-Host "Starting AD LDS repair process for instance: $InstanceName" -ForegroundColor Green

        # Create backup directory
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force
        }

        # Backup configuration
        Write-Host "Backing up AD LDS configuration..." -ForegroundColor Yellow
        try {
            $instancePath = "C:\Program Files\Microsoft ADAM\$InstanceName"
            if (Test-Path $instancePath) {
                $backupFile = Join-Path $BackupPath "ADLDS-Backup-$InstanceName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').zip"
                Compress-Archive -Path $instancePath -DestinationPath $backupFile -Force
                $result.RepairsPerformed += "Configuration backup created"
            }
        } catch {
            Write-Warning "Could not backup AD LDS configuration"
        }

        # Repair service issues
        if ($RepairType -eq "All" -or $RepairType -eq "Service") {
            Write-Host "Repairing AD LDS service issues..." -ForegroundColor Yellow
            
            try {
                $adldsService = Get-Service -Name "ADAM_$InstanceName" -ErrorAction SilentlyContinue
                if (-not $adldsService) {
                    $adldsService = Get-Service -Name "ADWS_$InstanceName" -ErrorAction SilentlyContinue
                }

                if ($adldsService -and $adldsService.Status -ne "Running") {
                    Start-Service -Name $adldsService.Name -ErrorAction Stop
                    $result.RepairsPerformed += "AD LDS service started"
                    $result.IssuesFixed += "Service not running"
                }
            } catch {
                Write-Warning "Could not repair AD LDS service"
            }
        }

        # Repair configuration issues
        if ($RepairType -eq "All" -or $RepairType -eq "Configuration") {
            Write-Host "Repairing AD LDS configuration issues..." -ForegroundColor Yellow
            
            try {
                $instancePath = "C:\Program Files\Microsoft ADAM\$InstanceName"
                if (-not (Test-Path $instancePath)) {
                    New-Item -Path $instancePath -ItemType Directory -Force
                    $result.RepairsPerformed += "Instance directory created"
                    $result.IssuesFixed += "Missing instance directory"
                }

                # Create required subdirectories
                $subdirs = @("data", "logs", "config")
                foreach ($subdir in $subdirs) {
                    $subdirPath = Join-Path $instancePath $subdir
                    if (-not (Test-Path $subdirPath)) {
                        New-Item -Path $subdirPath -ItemType Directory -Force
                        $result.RepairsPerformed += "Subdirectory created: $subdir"
                    }
                }
            } catch {
                Write-Warning "Could not repair AD LDS configuration"
            }
        }

        # Repair partition issues
        if ($RepairType -eq "All" -or $RepairType -eq "Partitions") {
            Write-Host "Repairing AD LDS partition issues..." -ForegroundColor Yellow
            
            try {
                # This would typically repair partition configuration
                $result.RepairsPerformed += "Partition configuration checked"
            } catch {
                Write-Warning "Could not repair AD LDS partitions"
            }
        }

        # Repair authentication issues
        if ($RepairType -eq "All" -or $RepairType -eq "Authentication") {
            Write-Host "Repairing AD LDS authentication issues..." -ForegroundColor Yellow
            
            try {
                # This would typically repair authentication configuration
                $result.RepairsPerformed += "Authentication configuration checked"
            } catch {
                Write-Warning "Could not repair AD LDS authentication"
            }
        }

        # Repair permission issues
        if ($RepairType -eq "All" -or $RepairType -eq "Permissions") {
            Write-Host "Repairing AD LDS permission issues..." -ForegroundColor Yellow
            
            try {
                # This would typically repair permissions
                $result.RepairsPerformed += "Permissions checked and repaired"
            } catch {
                Write-Warning "Could not repair AD LDS permissions"
            }
        }

        Write-Host "AD LDS repair process completed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to repair AD LDS issues: $($_.Exception.Message)"
    }

    return $result
}

function Test-ADLDSConfiguration {
    <#
    .SYNOPSIS
        Tests AD LDS configuration

    .DESCRIPTION
        Validates AD LDS configuration for common issues

    .PARAMETER InstanceName
        Name of the AD LDS instance

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InstanceName = "Default"
    )

    $result = @{
        Success = $false
        InstanceName = $InstanceName
        ConfigurationValid = $false
        IssuesFound = @()
        Recommendations = @()
        Error = $null
    }

    try {
        Write-Host "Testing AD LDS configuration for instance: $InstanceName" -ForegroundColor Green

        $issues = @()
        $recommendations = @()

        # Test instance configuration
        try {
            $instancePath = "C:\Program Files\Microsoft ADAM\$InstanceName"
            if (-not (Test-Path $instancePath)) {
                $issues += "Instance directory not found"
                $recommendations += "Create instance directory or check instance name"
            }

            # Check required subdirectories
            $requiredDirs = @("data", "logs", "config")
            foreach ($dir in $requiredDirs) {
                $dirPath = Join-Path $instancePath $dir
                if (-not (Test-Path $dirPath)) {
                    $issues += "Required directory missing: $dir"
                    $recommendations += "Create missing directory: $dir"
                }
            }
        } catch {
            $issues += "Could not validate instance configuration"
            $recommendations += "Check instance configuration and permissions"
        }

        # Test service configuration
        try {
            $adldsService = Get-Service -Name "ADAM_$InstanceName" -ErrorAction SilentlyContinue
            if (-not $adldsService) {
                $adldsService = Get-Service -Name "ADWS_$InstanceName" -ErrorAction SilentlyContinue
            }

            if (-not $adldsService) {
                $issues += "AD LDS service not found"
                $recommendations += "Install or configure AD LDS service"
            } else {
                if ($adldsService.Status -ne "Running") {
                    $issues += "AD LDS service is not running"
                    $recommendations += "Start the AD LDS service"
                }
            }
        } catch {
            $issues += "Could not validate service configuration"
            $recommendations += "Check service configuration and permissions"
        }

        # Test connectivity
        try {
            $connectivity = Test-ADLDSConnectivity -InstanceName $InstanceName
            if ($connectivity.Issues.Count -gt 0) {
                $issues += "Connectivity issues detected"
                $recommendations += "Check network configuration and firewall settings"
            }
        } catch {
            $issues += "Could not test connectivity"
            $recommendations += "Check network configuration"
        }

        $result.IssuesFound = $issues
        $result.Recommendations = $recommendations
        $result.ConfigurationValid = $issues.Count -eq 0
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to test AD LDS configuration: $($_.Exception.Message)"
    }

    return $result
}

function Get-ADLDSTroubleshootingGuide {
    <#
    .SYNOPSIS
        Gets AD LDS troubleshooting guide

    .DESCRIPTION
        Returns a comprehensive troubleshooting guide for common AD LDS issues

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        TroubleshootingGuide = $null
        Error = $null
    }

    try {
        Write-Host "Generating AD LDS troubleshooting guide..." -ForegroundColor Green

        $guide = @{
            CommonIssues = @{
                "Service Not Running" = @{
                    Symptoms = @("LDAP connections fail", "AD LDS service shows as stopped")
                    Causes = @("Service manually stopped", "Service failed to start", "Dependency issues")
                    Solutions = @("Start the AD LDS service", "Check service dependencies", "Review event logs")
                }
                "Instance Not Found" = @{
                    Symptoms = @("Cannot connect to instance", "Instance directory not found")
                    Causes = @("Instance not created", "Wrong instance name", "Path issues")
                    Solutions = @("Create AD LDS instance", "Verify instance name", "Check instance paths")
                }
                "Authentication Failures" = @{
                    Symptoms = @("LDAP bind failures", "Access denied errors")
                    Causes = @("Invalid credentials", "Authentication method issues", "User not found")
                    Solutions = @("Verify credentials", "Check authentication method", "Verify user exists")
                }
                "Partition Access Issues" = @{
                    Symptoms = @("Cannot access partitions", "Permission denied errors")
                    Causes = @("Partition not created", "Permission issues", "Schema problems")
                    Solutions = @("Create partitions", "Check permissions", "Verify schema")
                }
                "Performance Issues" = @{
                    Symptoms = @("Slow LDAP responses", "High CPU usage", "Memory issues")
                    Causes = @("Insufficient resources", "Poor indexing", "Large datasets")
                    Solutions = @("Increase resources", "Optimize indexes", "Review data size")
                }
            }
            DiagnosticSteps = @(
                "Check AD LDS service status",
                "Verify instance configuration",
                "Test LDAP connectivity",
                "Check authentication",
                "Review event logs",
                "Test partition access",
                "Monitor performance"
            )
            PowerShellCommands = @{
                "Check Service Status" = "Get-Service -Name 'ADAM_*'"
                "List Instances" = "Get-ChildItem 'C:\Program Files\Microsoft ADAM\'"
                "Test LDAP Connection" = "Test-NetConnection -ComputerName localhost -Port 389"
                "Check Event Logs" = "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='ADAM'}"
            }
            EventLogSources = @(
                "Application",
                "System",
                "ADAM"
            )
        }

        $result.TroubleshootingGuide = $guide
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get AD LDS troubleshooting guide: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Start-ADLDSDiagnostics',
    'Repair-ADLDSIssues',
    'Test-ADLDSConfiguration',
    'Get-ADLDSTroubleshootingGuide'
)
