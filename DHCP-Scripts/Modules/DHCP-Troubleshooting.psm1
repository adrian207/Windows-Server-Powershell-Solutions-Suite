#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DHCP Troubleshooting PowerShell Module

.DESCRIPTION
    This module provides troubleshooting functions for DHCP operations including
    diagnostics, automated repair, and issue resolution.

.NOTES
    Author: DHCP PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module DhcpServer -ErrorAction Stop
    Import-Module ServerManager -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-DHCPServiceHealth {
    <#
    .SYNOPSIS
        Tests DHCP service health

    .DESCRIPTION
        Performs comprehensive health checks on DHCP service

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $health = @{
        ServiceRunning = $false
        ServiceStartType = "Unknown"
        ServiceDependencies = @()
        ConfigurationValid = $false
        ScopesActive = $false
        LeasesValid = $false
        Issues = @()
    }

    try {
        # Check service status
        $dhcpService = Get-Service -Name DHCPServer -ErrorAction Stop
        $health.ServiceRunning = $dhcpService.Status -eq "Running"
        $health.ServiceStartType = $dhcpService.StartType

        # Check service dependencies
        $dependencies = Get-Service -Name DHCPServer -DependentServices -ErrorAction SilentlyContinue
        $health.ServiceDependencies = $dependencies | ForEach-Object { $_.Name }

        # Check configuration
        try {
            $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
            $health.ConfigurationValid = $dhcpConfig.Authorized
        } catch {
            $health.Issues += "Configuration validation failed"
        }

        # Check scopes
        try {
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
            $activeScopes = $scopes | Where-Object { $_.State -eq "Active" }
            $health.ScopesActive = $activeScopes.Count -gt 0
        } catch {
            $health.Issues += "Scope validation failed"
        }

        # Check leases
        try {
            $leases = Get-DhcpServerv4Lease -ErrorAction Stop
            $health.LeasesValid = $leases.Count -ge 0
        } catch {
            $health.Issues += "Lease validation failed"
        }

    } catch {
        $health.Issues += "Service health check failed: $($_.Exception.Message)"
    }

    return $health
}

function Get-DHCPEventLogs {
    <#
    .SYNOPSIS
        Gets DHCP event logs

    .DESCRIPTION
        Collects relevant DHCP event logs for troubleshooting

    .PARAMETER Hours
        Number of hours to look back

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Hours = 24
    )

    $logs = @{
        Errors = @()
        Warnings = @()
        Information = @()
        Critical = @()
    }

    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        
        # Get DHCP server logs
        $dhcpLogs = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-DHCP-Server/Operational"
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        foreach ($log in $dhcpLogs) {
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

        # Get system logs related to DHCP
        $systemLogs = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            StartTime = $startTime
            ProviderName = "DHCPServer"
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
        Write-Warning "Could not collect DHCP event logs: $($_.Exception.Message)"
    }

    return $logs
}

function Test-DHCPConnectivity {
    <#
    .SYNOPSIS
        Tests DHCP connectivity

    .DESCRIPTION
        Tests DHCP server connectivity and network reachability

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $connectivity = @{
        LocalBinding = $false
        NetworkInterfaces = @()
        Port67Open = $false
        Port68Open = $false
        Issues = @()
    }

    try {
        # Check local binding
        $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
        $connectivity.LocalBinding = $dhcpConfig.Authorized

        # Check network interfaces
        $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $connectivity.NetworkInterfaces = $interfaces | ForEach-Object {
            @{
                Name = $_.Name
                Status = $_.Status
                IPAddress = (Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).IPAddress
            }
        }

        # Check DHCP ports
        try {
            $port67 = Get-NetTCPConnection -LocalPort 67 -ErrorAction SilentlyContinue
            $connectivity.Port67Open = $port67 -ne $null
        } catch {
            $connectivity.Issues += "Port 67 check failed"
        }

        try {
            $port68 = Get-NetUDPConnection -LocalPort 68 -ErrorAction SilentlyContinue
            $connectivity.Port68Open = $port68 -ne $null
        } catch {
            $connectivity.Issues += "Port 68 check failed"
        }

    } catch {
        $connectivity.Issues += "Connectivity test failed: $($_.Exception.Message)"
    }

    return $connectivity
}

#endregion

#region Public Functions

function Start-DHCPDiagnostics {
    <#
    .SYNOPSIS
        Starts comprehensive DHCP diagnostics

    .DESCRIPTION
        Performs comprehensive DHCP diagnostics and returns detailed results

    .PARAMETER IncludeEventLogs
        Include event log analysis

    .PARAMETER IncludeConnectivity
        Include connectivity tests

    .PARAMETER IncludePerformance
        Include performance analysis

    .PARAMETER LogPath
        Path for diagnostic logs

    .EXAMPLE
        Start-DHCPDiagnostics -IncludeEventLogs -IncludeConnectivity -LogPath "C:\DHCP\Diagnostics"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$IncludeEventLogs,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeConnectivity,

        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformance,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\DHCP\Diagnostics"
    )

    $result = @{
        Success = $false
        Diagnostics = $null
        IssuesFound = @()
        Recommendations = @()
        Error = $null
    }

    try {
        Write-Host "Starting comprehensive DHCP diagnostics..." -ForegroundColor Green

        # Create log directory
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force
        }

        $diagnostics = @{
            Timestamp = Get-Date
            ServiceHealth = $null
            EventLogs = $null
            Connectivity = $null
            Performance = $null
            Configuration = $null
        }

        # Service health check
        Write-Host "Checking DHCP service health..." -ForegroundColor Yellow
        $diagnostics.ServiceHealth = Test-DHCPServiceHealth

        # Event log analysis
        if ($IncludeEventLogs) {
            Write-Host "Analyzing DHCP event logs..." -ForegroundColor Yellow
            $diagnostics.EventLogs = Get-DHCPEventLogs -Hours 24
        }

        # Connectivity tests
        if ($IncludeConnectivity) {
            Write-Host "Testing DHCP connectivity..." -ForegroundColor Yellow
            $diagnostics.Connectivity = Test-DHCPConnectivity
        }

        # Performance analysis
        if ($IncludePerformance) {
            Write-Host "Analyzing DHCP performance..." -ForegroundColor Yellow
            try {
                Import-Module "..\..\Modules\DHCP-Monitoring.psm1" -Force
                $diagnostics.Performance = Get-DHCPHealthStatus
            } catch {
                Write-Warning "Could not load performance analysis module"
            }
        }

        # Configuration analysis
        Write-Host "Analyzing DHCP configuration..." -ForegroundColor Yellow
        try {
            $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
            $leases = Get-DhcpServerv4Lease -ErrorAction Stop

            $diagnostics.Configuration = @{
                ServerConfiguration = $dhcpConfig
                ScopeCount = $scopes.Count
                ActiveScopes = ($scopes | Where-Object { $_.State -eq "Active" }).Count
                LeaseCount = $leases.Count
                ActiveLeases = ($leases | Where-Object { $_.AddressState -eq "Active" }).Count
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
            $issues += "DHCP service is not running"
            $recommendations += "Start the DHCP service"
        }

        if (-not $diagnostics.ServiceHealth.ConfigurationValid) {
            $issues += "DHCP server is not authorized"
            $recommendations += "Authorize the DHCP server in Active Directory"
        }

        if (-not $diagnostics.ServiceHealth.ScopesActive) {
            $issues += "No active DHCP scopes found"
            $recommendations += "Create and activate DHCP scopes"
        }

        # Event log issues
        if ($IncludeEventLogs -and $diagnostics.EventLogs) {
            if ($diagnostics.EventLogs.Errors.Count -gt 0) {
                $issues += "DHCP errors found in event logs"
                $recommendations += "Review and resolve DHCP errors"
            }

            if ($diagnostics.EventLogs.Critical.Count -gt 0) {
                $issues += "Critical DHCP events found"
                $recommendations += "Immediately address critical DHCP issues"
            }
        }

        # Connectivity issues
        if ($IncludeConnectivity -and $diagnostics.Connectivity) {
            if ($diagnostics.Connectivity.Issues.Count -gt 0) {
                $issues += "DHCP connectivity issues detected"
                $recommendations += "Check network configuration and firewall settings"
            }
        }

        # Performance issues
        if ($IncludePerformance -and $diagnostics.Performance) {
            if ($diagnostics.Performance.HealthStatus.OverallHealth -eq "Critical") {
                $issues += "Critical DHCP performance issues detected"
                $recommendations += "Investigate and resolve performance issues"
            }
        }

        $result.Diagnostics = $diagnostics
        $result.IssuesFound = $issues
        $result.Recommendations = $recommendations

        # Save diagnostics to file
        $diagnosticsFile = Join-Path $LogPath "DHCP-Diagnostics-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $diagnostics | ConvertTo-Json -Depth 5 | Out-File -FilePath $diagnosticsFile

        Write-Host "DHCP diagnostics completed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to start DHCP diagnostics: $($_.Exception.Message)"
    }

    return $result
}

function Repair-DHCPIssues {
    <#
    .SYNOPSIS
        Repairs common DHCP issues

    .DESCRIPTION
        Automatically repairs common DHCP issues

    .PARAMETER RepairType
        Type of repair to perform

    .PARAMETER BackupPath
        Path for backup before repair

    .EXAMPLE
        Repair-DHCPIssues -RepairType "All" -BackupPath "C:\DHCP\Backup"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Service", "Configuration", "Scopes", "Leases", "Authorization")]
        [string]$RepairType = "All",

        [Parameter(Mandatory = $false)]
        [string]$BackupPath = "C:\DHCP\Backup"
    )

    $result = @{
        Success = $false
        RepairsPerformed = @()
        IssuesFixed = @()
        Error = $null
    }

    try {
        Write-Host "Starting DHCP repair process..." -ForegroundColor Green

        # Create backup directory
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force
        }

        # Backup configuration
        Write-Host "Backing up DHCP configuration..." -ForegroundColor Yellow
        try {
            $backupFile = Join-Path $BackupPath "DHCP-Backup-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').xml"
            Export-DhcpServer -File $backupFile -ErrorAction Stop
            $result.RepairsPerformed += "Configuration backup created"
        } catch {
            Write-Warning "Could not backup DHCP configuration"
        }

        # Repair service issues
        if ($RepairType -eq "All" -or $RepairType -eq "Service") {
            Write-Host "Repairing DHCP service issues..." -ForegroundColor Yellow
            
            try {
                $dhcpService = Get-Service -Name DHCPServer -ErrorAction Stop
                if ($dhcpService.Status -ne "Running") {
                    Start-Service -Name DHCPServer -ErrorAction Stop
                    $result.RepairsPerformed += "DHCP service started"
                    $result.IssuesFixed += "Service not running"
                }
            } catch {
                Write-Warning "Could not repair DHCP service"
            }
        }

        # Repair configuration issues
        if ($RepairType -eq "All" -or $RepairType -eq "Configuration") {
            Write-Host "Repairing DHCP configuration issues..." -ForegroundColor Yellow
            
            try {
                $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
                if (-not $dhcpConfig.Authorized) {
                    # This would typically require domain admin privileges
                    Write-Host "DHCP server authorization requires domain admin privileges" -ForegroundColor Yellow
                    $result.RepairsPerformed += "Authorization check performed"
                }
            } catch {
                Write-Warning "Could not repair DHCP configuration"
            }
        }

        # Repair scope issues
        if ($RepairType -eq "All" -or $RepairType -eq "Scopes") {
            Write-Host "Repairing DHCP scope issues..." -ForegroundColor Yellow
            
            try {
                $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
                $inactiveScopes = $scopes | Where-Object { $_.State -eq "Inactive" }
                
                foreach ($scope in $inactiveScopes) {
                    try {
                        Set-DhcpServerv4Scope -ScopeId $scope.ScopeId -State Active -ErrorAction Stop
                        $result.RepairsPerformed += "Scope $($scope.ScopeId) activated"
                        $result.IssuesFixed += "Inactive scope: $($scope.ScopeId)"
                    } catch {
                        Write-Warning "Could not activate scope: $($scope.ScopeId)"
                    }
                }
            } catch {
                Write-Warning "Could not repair DHCP scopes"
            }
        }

        # Repair lease issues
        if ($RepairType -eq "All" -or $RepairType -eq "Leases") {
            Write-Host "Repairing DHCP lease issues..." -ForegroundColor Yellow
            
            try {
                $leases = Get-DhcpServerv4Lease -ErrorAction Stop
                $declinedLeases = $leases | Where-Object { $_.AddressState -eq "Declined" }
                
                foreach ($lease in $declinedLeases) {
                    try {
                        Remove-DhcpServerv4Lease -IPAddress $lease.IPAddress -ErrorAction Stop
                        $result.RepairsPerformed += "Declined lease removed: $($lease.IPAddress)"
                        $result.IssuesFixed += "Declined lease: $($lease.IPAddress)"
                    } catch {
                        Write-Warning "Could not remove declined lease: $($lease.IPAddress)"
                    }
                }
            } catch {
                Write-Warning "Could not repair DHCP leases"
            }
        }

        Write-Host "DHCP repair process completed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to repair DHCP issues: $($_.Exception.Message)"
    }

    return $result
}

function Test-DHCPConfiguration {
    <#
    .SYNOPSIS
        Tests DHCP configuration

    .DESCRIPTION
        Validates DHCP configuration for common issues

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        ConfigurationValid = $false
        IssuesFound = @()
        Recommendations = @()
        Error = $null
    }

    try {
        Write-Host "Testing DHCP configuration..." -ForegroundColor Green

        $issues = @()
        $recommendations = @()

        # Test server configuration
        try {
            $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
            
            if (-not $dhcpConfig.Authorized) {
                $issues += "DHCP server is not authorized"
                $recommendations += "Authorize the DHCP server in Active Directory"
            }

            if (-not $dhcpConfig.AuditLogEnabled) {
                $issues += "Audit logging is disabled"
                $recommendations += "Enable audit logging for compliance"
            }

        } catch {
            $issues += "Could not retrieve server configuration"
            $recommendations += "Check DHCP service status and permissions"
        }

        # Test scopes
        try {
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
            
            if ($scopes.Count -eq 0) {
                $issues += "No DHCP scopes configured"
                $recommendations += "Create DHCP scopes for IP address assignment"
            }

            $inactiveScopes = $scopes | Where-Object { $_.State -eq "Inactive" }
            if ($inactiveScopes.Count -gt 0) {
                $issues += "Inactive scopes found"
                $recommendations += "Activate inactive scopes or remove unused scopes"
            }

            # Check for scope overlaps
            $scopeRanges = $scopes | ForEach-Object {
                @{
                    ScopeId = $_.ScopeId
                    StartRange = $_.StartRange
                    EndRange = $_.EndRange
                }
            }

            for ($i = 0; $i -lt $scopeRanges.Count; $i++) {
                for ($j = $i + 1; $j -lt $scopeRanges.Count; $j++) {
                    $range1 = $scopeRanges[$i]
                    $range2 = $scopeRanges[$j]
                    
                    if (($range1.StartRange -le $range2.EndRange) -and ($range1.EndRange -ge $range2.StartRange)) {
                        $issues += "Scope overlap detected between $($range1.ScopeId) and $($range2.ScopeId)"
                        $recommendations += "Resolve scope overlap to prevent IP conflicts"
                    }
                }
            }

        } catch {
            $issues += "Could not retrieve scope configuration"
            $recommendations += "Check DHCP service status and permissions"
        }

        # Test reservations
        try {
            $reservations = Get-DhcpServerv4Reservation -ErrorAction Stop
            
            $duplicateReservations = $reservations | Group-Object IPAddress | Where-Object { $_.Count -gt 1 }
            if ($duplicateReservations.Count -gt 0) {
                $issues += "Duplicate reservations found"
                $recommendations += "Remove duplicate reservations"
            }

        } catch {
            Write-Warning "Could not retrieve reservation configuration"
        }

        # Test options
        try {
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
            
            foreach ($scope in $scopes) {
                $options = Get-DhcpServerv4OptionValue -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                
                $routerOption = $options | Where-Object { $_.OptionId -eq 3 }
                if (-not $routerOption) {
                    $issues += "No router option configured for scope $($scope.ScopeId)"
                    $recommendations += "Configure router option (Option 3) for scope $($scope.ScopeId)"
                }

                $dnsOption = $options | Where-Object { $_.OptionId -eq 6 }
                if (-not $dnsOption) {
                    $issues += "No DNS server option configured for scope $($scope.ScopeId)"
                    $recommendations += "Configure DNS server option (Option 6) for scope $($scope.ScopeId)"
                }
            }

        } catch {
            Write-Warning "Could not retrieve option configuration"
        }

        $result.IssuesFound = $issues
        $result.Recommendations = $recommendations
        $result.ConfigurationValid = $issues.Count -eq 0
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to test DHCP configuration: $($_.Exception.Message)"
    }

    return $result
}

function Get-DHCPTroubleshootingGuide {
    <#
    .SYNOPSIS
        Gets DHCP troubleshooting guide

    .DESCRIPTION
        Returns a comprehensive troubleshooting guide for common DHCP issues

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
        Write-Host "Generating DHCP troubleshooting guide..." -ForegroundColor Green

        $guide = @{
            CommonIssues = @{
                "Service Not Running" = @{
                    Symptoms = @("Clients cannot obtain IP addresses", "DHCP service shows as stopped")
                    Causes = @("Service manually stopped", "Service failed to start", "Dependency issues")
                    Solutions = @("Start the DHCP service", "Check service dependencies", "Review event logs")
                }
                "Server Not Authorized" = @{
                    Symptoms = @("DHCP server shows as unauthorized", "Clients cannot obtain IP addresses")
                    Causes = @("Server not authorized in AD", "Domain controller issues", "Permission problems")
                    Solutions = @("Authorize server in Active Directory", "Check domain controller connectivity", "Verify permissions")
                }
                "No Active Scopes" = @{
                    Symptoms = @("Clients cannot obtain IP addresses", "No IP addresses available")
                    Causes = @("Scopes not created", "Scopes inactive", "Scope configuration issues")
                    Solutions = @("Create DHCP scopes", "Activate inactive scopes", "Check scope configuration")
                }
                "IP Conflicts" = @{
                    Symptoms = @("Clients report IP conflicts", "Declined leases", "Network connectivity issues")
                    Causes = @("Static IP conflicts", "Scope overlaps", "Reservation conflicts")
                    Solutions = @("Check for static IP conflicts", "Resolve scope overlaps", "Review reservations")
                }
                "High Decline Rate" = @{
                    Symptoms = @("Many declined leases", "Clients cannot obtain IP addresses")
                    Causes = @("IP conflicts", "Network issues", "Client configuration problems")
                    Solutions = @("Investigate IP conflicts", "Check network connectivity", "Review client configuration")
                }
            }
            DiagnosticSteps = @(
                "Check DHCP service status",
                "Verify server authorization",
                "Review DHCP scopes",
                "Check for IP conflicts",
                "Analyze event logs",
                "Test network connectivity",
                "Verify client configuration"
            )
            PowerShellCommands = @{
                "Check Service Status" = "Get-Service -Name DHCPServer"
                "Get Server Configuration" = "Get-DhcpServerConfiguration"
                "List Scopes" = "Get-DhcpServerv4Scope"
                "Get Leases" = "Get-DhcpServerv4Lease"
                "Check Reservations" = "Get-DhcpServerv4Reservation"
                "Get Statistics" = "Get-DhcpServerv4Statistics"
            }
            EventLogSources = @(
                "Microsoft-Windows-DHCP-Server/Operational",
                "System",
                "Application"
            )
        }

        $result.TroubleshootingGuide = $guide
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DHCP troubleshooting guide: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Start-DHCPDiagnostics',
    'Repair-DHCPIssues',
    'Test-DHCPConfiguration',
    'Get-DHCPTroubleshootingGuide'
)
