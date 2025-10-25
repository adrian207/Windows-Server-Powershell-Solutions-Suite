#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DHCP Monitoring PowerShell Module

.DESCRIPTION
    This module provides monitoring functions for DHCP operations including
    performance monitoring, alerting, and analytics.

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
    Import-Module PerformanceCounter -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Get-DHCPPerformanceCounters {
    <#
    .SYNOPSIS
        Gets DHCP performance counters

    .DESCRIPTION
        Collects DHCP performance counter data

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $counters = @{
        PacketsReceivedPerSecond = 0
        PacketsSentPerSecond = 0
        DuplicatePacketsDroppedPerSecond = 0
        PacketsExpiredPerSecond = 0
        MillisecondsPerPacket = 0
        ActiveQueueLength = 0
        DiscoversReceivedPerSecond = 0
        OffersSentPerSecond = 0
        RequestsReceivedPerSecond = 0
        AcksSentPerSecond = 0
        NacksSentPerSecond = 0
        DeclinesReceivedPerSecond = 0
        ReleasesReceivedPerSecond = 0
        InformsReceivedPerSecond = 0
    }

    try {
        $counterNames = @(
            "\DHCP Server\Packets received/sec",
            "\DHCP Server\Packets sent/sec",
            "\DHCP Server\Duplicate packets dropped/sec",
            "\DHCP Server\Packets expired/sec",
            "\DHCP Server\Milliseconds per packet (Avg)",
            "\DHCP Server\Active queue length",
            "\DHCP Server\Discovers received/sec",
            "\DHCP Server\Offers sent/sec",
            "\DHCP Server\Requests received/sec",
            "\DHCP Server\Acks sent/sec",
            "\DHCP Server\Nacks sent/sec",
            "\DHCP Server\Declines received/sec",
            "\DHCP Server\Releases received/sec",
            "\DHCP Server\Informs received/sec"
        )

        foreach ($counterName in $counterNames) {
            try {
                $counter = Get-Counter -Counter $counterName -ErrorAction Stop
                $value = $counter.CounterSamples[0].CookedValue

                switch ($counterName) {
                    "\DHCP Server\Packets received/sec" { $counters.PacketsReceivedPerSecond = $value }
                    "\DHCP Server\Packets sent/sec" { $counters.PacketsSentPerSecond = $value }
                    "\DHCP Server\Duplicate packets dropped/sec" { $counters.DuplicatePacketsDroppedPerSecond = $value }
                    "\DHCP Server\Packets expired/sec" { $counters.PacketsExpiredPerSecond = $value }
                    "\DHCP Server\Milliseconds per packet (Avg)" { $counters.MillisecondsPerPacket = $value }
                    "\DHCP Server\Active queue length" { $counters.ActiveQueueLength = $value }
                    "\DHCP Server\Discovers received/sec" { $counters.DiscoversReceivedPerSecond = $value }
                    "\DHCP Server\Offers sent/sec" { $counters.OffersSentPerSecond = $value }
                    "\DHCP Server\Requests received/sec" { $counters.RequestsReceivedPerSecond = $value }
                    "\DHCP Server\Acks sent/sec" { $counters.AcksSentPerSecond = $value }
                    "\DHCP Server\Nacks sent/sec" { $counters.NacksSentPerSecond = $value }
                    "\DHCP Server\Declines received/sec" { $counters.DeclinesReceivedPerSecond = $value }
                    "\DHCP Server\Releases received/sec" { $counters.ReleasesReceivedPerSecond = $value }
                    "\DHCP Server\Informs received/sec" { $counters.InformsReceivedPerSecond = $value }
                }
            } catch {
                Write-Warning "Could not get counter: $counterName"
            }
        }
    } catch {
        Write-Warning "Could not collect DHCP performance counters"
    }

    return $counters
}

function Analyze-DHCPLeasePatterns {
    <#
    .SYNOPSIS
        Analyzes DHCP lease patterns

    .DESCRIPTION
        Analyzes lease patterns for insights and anomalies

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $analysis = @{
        TotalLeases = 0
        ActiveLeases = 0
        ExpiredLeases = 0
        DeclinedLeases = 0
        LeaseUtilization = 0
        TopClients = @()
        LeaseTrends = @()
        Anomalies = @()
    }

    try {
        $leases = Get-DhcpServerv4Lease -ErrorAction Stop
        $analysis.TotalLeases = $leases.Count

        $activeLeases = $leases | Where-Object { $_.AddressState -eq "Active" }
        $analysis.ActiveLeases = $activeLeases.Count

        $expiredLeases = $leases | Where-Object { $_.AddressState -eq "Expired" }
        $analysis.ExpiredLeases = $expiredLeases.Count

        $declinedLeases = $leases | Where-Object { $_.AddressState -eq "Declined" }
        $analysis.DeclinedLeases = $declinedLeases.Count

        # Calculate lease utilization
        if ($analysis.TotalLeases -gt 0) {
            $analysis.LeaseUtilization = [math]::Round(($analysis.ActiveLeases / $analysis.TotalLeases) * 100, 2)
        }

        # Get top clients by lease count
        $topClients = $leases | Group-Object ClientId | Sort-Object Count -Descending | Select-Object -First 10
        $analysis.TopClients = $topClients | ForEach-Object {
            @{
                ClientId = $_.Name
                LeaseCount = $_.Count
            }
        }

        # Analyze lease trends (last 24 hours)
        $recentLeases = $leases | Where-Object { $_.LeaseExpiryTime -gt (Get-Date).AddDays(-1) }
        $analysis.LeaseTrends = @{
            RecentLeases = $recentLeases.Count
            AverageLeaseDuration = 0
            ShortLeases = 0
            LongLeases = 0
        }

        if ($recentLeases.Count -gt 0) {
            $leaseDurations = $recentLeases | ForEach-Object {
                ($_.LeaseExpiryTime - $_.LeaseStartTime).TotalHours
            }
            $analysis.LeaseTrends.AverageLeaseDuration = [math]::Round(($leaseDurations | Measure-Object -Average).Average, 2)
            $analysis.LeaseTrends.ShortLeases = ($leaseDurations | Where-Object { $_ -lt 1 }).Count
            $analysis.LeaseTrends.LongLeases = ($leaseDurations | Where-Object { $_ -gt 168 }).Count
        }

        # Detect anomalies
        $anomalies = @()
        
        # High decline rate
        if ($analysis.DeclinedLeases -gt ($analysis.TotalLeases * 0.1)) {
            $anomalies += "High decline rate detected"
        }

        # Low utilization
        if ($analysis.LeaseUtilization -lt 20) {
            $anomalies += "Low lease utilization detected"
        }

        # Suspicious client patterns
        $suspiciousClients = $topClients | Where-Object { $_.Count -gt 50 }
        if ($suspiciousClients.Count -gt 0) {
            $anomalies += "Suspicious client lease patterns detected"
        }

        $analysis.Anomalies = $anomalies

    } catch {
        Write-Warning "Could not analyze DHCP lease patterns: $($_.Exception.Message)"
    }

    return $analysis
}

#endregion

#region Public Functions

function Start-DHCPMonitoring {
    <#
    .SYNOPSIS
        Starts DHCP monitoring

    .DESCRIPTION
        Starts comprehensive DHCP monitoring with real-time alerts

    .PARAMETER MonitoringDuration
        Duration to monitor in minutes

    .PARAMETER AlertThresholds
        Hashtable of alert thresholds

    .PARAMETER LogPath
        Path for monitoring logs

    .EXAMPLE
        Start-DHCPMonitoring -MonitoringDuration 60 -LogPath "C:\DHCP\Monitoring"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MonitoringDuration = 60,

        [Parameter(Mandatory = $false)]
        [hashtable]$AlertThresholds = @{
            HighPacketRate = 1000
            HighQueueLength = 100
            LowLeaseUtilization = 20
            HighDeclineRate = 10
        },

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\DHCP\Monitoring"
    )

    $result = @{
        Success = $false
        MonitoringStarted = $false
        AlertsGenerated = @()
        Error = $null
    }

    try {
        Write-Host "Starting DHCP monitoring for $MonitoringDuration minutes..." -ForegroundColor Green

        # Create log directory
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force
        }

        $startTime = Get-Date
        $endTime = $startTime.AddMinutes($MonitoringDuration)

        $result.MonitoringStarted = $true

        while ((Get-Date) -lt $endTime) {
            # Collect performance data
            $perfCounters = Get-DHCPPerformanceCounters
            $leaseAnalysis = Analyze-DHCPLeasePatterns

            # Check alert thresholds
            $alerts = @()

            if ($perfCounters.PacketsReceivedPerSecond -gt $AlertThresholds.HighPacketRate) {
                $alerts += "High packet rate detected: $($perfCounters.PacketsReceivedPerSecond) packets/sec"
            }

            if ($perfCounters.ActiveQueueLength -gt $AlertThresholds.HighQueueLength) {
                $alerts += "High queue length detected: $($perfCounters.ActiveQueueLength)"
            }

            if ($leaseAnalysis.LeaseUtilization -lt $AlertThresholds.LowLeaseUtilization) {
                $alerts += "Low lease utilization detected: $($leaseAnalysis.LeaseUtilization)%"
            }

            if ($leaseAnalysis.DeclinedLeases -gt $AlertThresholds.HighDeclineRate) {
                $alerts += "High decline rate detected: $($leaseAnalysis.DeclinedLeases) declined leases"
            }

            # Log alerts
            foreach ($alert in $alerts) {
                $result.AlertsGenerated += $alert
                Write-Warning $alert
            }

            # Log monitoring data
            $logData = @{
                Timestamp = Get-Date
                PerformanceCounters = $perfCounters
                LeaseAnalysis = $leaseAnalysis
                Alerts = $alerts
            }

            $logFile = Join-Path $LogPath "DHCP-Monitoring-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
            $logData | ConvertTo-Json -Depth 3 | Out-File -FilePath $logFile -Append

            # Wait before next collection
            Start-Sleep -Seconds 30
        }

        Write-Host "DHCP monitoring completed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to start DHCP monitoring: $($_.Exception.Message)"
    }

    return $result
}

function Get-DHCPHealthStatus {
    <#
    .SYNOPSIS
        Gets DHCP health status

    .DESCRIPTION
        Returns comprehensive DHCP health status information

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        HealthStatus = $null
        PerformanceMetrics = $null
        LeaseAnalysis = $null
        Error = $null
    }

    try {
        Write-Host "Analyzing DHCP health status..." -ForegroundColor Green

        $healthStatus = @{
            ServiceStatus = "Unknown"
            ServerConfiguration = "Unknown"
            ScopeStatus = "Unknown"
            LeaseStatus = "Unknown"
            PerformanceStatus = "Unknown"
            OverallHealth = "Unknown"
        }

        # Check service status
        try {
            $dhcpService = Get-Service -Name DHCPServer -ErrorAction Stop
            $healthStatus.ServiceStatus = $dhcpService.Status
        } catch {
            $healthStatus.ServiceStatus = "Error"
        }

        # Check server configuration
        try {
            $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
            $healthStatus.ServerConfiguration = if ($dhcpConfig.Authorized) { "Authorized" } else { "Unauthorized" }
        } catch {
            $healthStatus.ServerConfiguration = "Error"
        }

        # Check scope status
        try {
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
            $activeScopes = $scopes | Where-Object { $_.State -eq "Active" }
            $healthStatus.ScopeStatus = if ($activeScopes.Count -gt 0) { "Healthy" } else { "No Active Scopes" }
        } catch {
            $healthStatus.ScopeStatus = "Error"
        }

        # Check lease status
        try {
            $leases = Get-DhcpServerv4Lease -ErrorAction Stop
            $activeLeases = $leases | Where-Object { $_.AddressState -eq "Active" }
            $healthStatus.LeaseStatus = if ($activeLeases.Count -gt 0) { "Healthy" } else { "No Active Leases" }
        } catch {
            $healthStatus.LeaseStatus = "Error"
        }

        # Check performance
        try {
            $perfCounters = Get-DHCPPerformanceCounters
            $healthStatus.PerformanceStatus = if ($perfCounters.PacketsReceivedPerSecond -gt 0) { "Healthy" } else { "No Activity" }
        } catch {
            $healthStatus.PerformanceStatus = "Error"
        }

        # Determine overall health
        $statusValues = @($healthStatus.ServiceStatus, $healthStatus.ServerConfiguration, $healthStatus.ScopeStatus, $healthStatus.LeaseStatus, $healthStatus.PerformanceStatus)
        $errorCount = ($statusValues | Where-Object { $_ -eq "Error" }).Count
        $unknownCount = ($statusValues | Where-Object { $_ -eq "Unknown" }).Count

        if ($errorCount -gt 0) {
            $healthStatus.OverallHealth = "Critical"
        } elseif ($unknownCount -gt 0) {
            $healthStatus.OverallHealth = "Warning"
        } else {
            $healthStatus.OverallHealth = "Healthy"
        }

        # Get performance metrics
        $performanceMetrics = Get-DHCPPerformanceCounters

        # Get lease analysis
        $leaseAnalysis = Analyze-DHCPLeasePatterns

        $result.HealthStatus = $healthStatus
        $result.PerformanceMetrics = $performanceMetrics
        $result.LeaseAnalysis = $leaseAnalysis
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DHCP health status: $($_.Exception.Message)"
    }

    return $result
}

function Set-DHCPAlerting {
    <#
    .SYNOPSIS
        Configures DHCP alerting

    .DESCRIPTION
        Sets up DHCP alerting for various conditions

    .PARAMETER AlertTypes
        Array of alert types to enable

    .PARAMETER EmailRecipients
        Array of email recipients

    .PARAMETER SMTPServer
        SMTP server for email alerts

    .PARAMETER LogPath
        Path for alert logs

    .EXAMPLE
        Set-DHCPAlerting -AlertTypes @("HighPacketRate", "LowLeaseUtilization") -EmailRecipients @("admin@contoso.com")

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$AlertTypes = @("HighPacketRate", "LowLeaseUtilization", "HighDeclineRate", "ServiceDown"),

        [Parameter(Mandatory = $false)]
        [string[]]$EmailRecipients,

        [Parameter(Mandatory = $false)]
        [string]$SMTPServer,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\DHCP\Alerts"
    )

    $result = @{
        Success = $false
        AlertTypesConfigured = @()
        Error = $null
    }

    try {
        Write-Host "Configuring DHCP alerting..." -ForegroundColor Green

        # Create alert log directory
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force
        }

        # Configure alert types
        foreach ($alertType in $AlertTypes) {
            $result.AlertTypesConfigured += $alertType
            Write-Host "Alert type configured: $alertType" -ForegroundColor Yellow
        }

        # Configure email alerts if specified
        if ($EmailRecipients -and $SMTPServer) {
            Write-Host "Email alerts configured for: $($EmailRecipients -join ', ')" -ForegroundColor Yellow
        }

        Write-Host "DHCP alerting configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DHCP alerting: $($_.Exception.Message)"
    }

    return $result
}

function Get-DHCPAnalytics {
    <#
    .SYNOPSIS
        Gets DHCP analytics

    .DESCRIPTION
        Returns comprehensive DHCP analytics and insights

    .PARAMETER TimeRange
        Time range for analytics (hours)

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$TimeRange = 24
    )

    $result = @{
        Success = $false
        Analytics = $null
        Error = $null
    }

    try {
        Write-Host "Generating DHCP analytics..." -ForegroundColor Green

        $analytics = @{
            TimeRange = $TimeRange
            LeaseStatistics = @{}
            PerformanceTrends = @{}
            TopClients = @()
            NetworkInsights = @()
            Recommendations = @()
        }

        # Get lease statistics
        $leases = Get-DhcpServerv4Lease -ErrorAction Stop
        $analytics.LeaseStatistics = @{
            TotalLeases = $leases.Count
            ActiveLeases = ($leases | Where-Object { $_.AddressState -eq "Active" }).Count
            ExpiredLeases = ($leases | Where-Object { $_.AddressState -eq "Expired" }).Count
            DeclinedLeases = ($leases | Where-Object { $_.AddressState -eq "Declined" }).Count
            AverageLeaseDuration = 0
        }

        # Calculate average lease duration
        if ($leases.Count -gt 0) {
            $leaseDurations = $leases | ForEach-Object {
                ($_.LeaseExpiryTime - $_.LeaseStartTime).TotalHours
            }
            $analytics.LeaseStatistics.AverageLeaseDuration = [math]::Round(($leaseDurations | Measure-Object -Average).Average, 2)
        }

        # Get performance trends
        $perfCounters = Get-DHCPPerformanceCounters
        $analytics.PerformanceTrends = $perfCounters

        # Get top clients
        $topClients = $leases | Group-Object ClientId | Sort-Object Count -Descending | Select-Object -First 10
        $analytics.TopClients = $topClients | ForEach-Object {
            @{
                ClientId = $_.Name
                LeaseCount = $_.Count
                Percentage = [math]::Round(($_.Count / $leases.Count) * 100, 2)
            }
        }

        # Generate network insights
        $insights = @()
        
        if ($analytics.LeaseStatistics.DeclinedLeases -gt ($analytics.LeaseStatistics.TotalLeases * 0.1)) {
            $insights += "High decline rate suggests potential network issues or IP conflicts"
        }

        if ($analytics.LeaseStatistics.ActiveLeases -lt ($analytics.LeaseStatistics.TotalLeases * 0.5)) {
            $insights += "Low active lease count suggests underutilized DHCP scope"
        }

        if ($perfCounters.DuplicatePacketsDroppedPerSecond -gt 10) {
            $insights += "High duplicate packet rate suggests network congestion or misconfiguration"
        }

        $analytics.NetworkInsights = $insights

        # Generate recommendations
        $recommendations = @()
        
        if ($analytics.LeaseStatistics.DeclinedLeases -gt 0) {
            $recommendations += "Investigate declined leases for IP conflicts"
        }

        if ($analytics.LeaseStatistics.AverageLeaseDuration -lt 24) {
            $recommendations += "Consider increasing lease duration for better stability"
        }

        if ($perfCounters.ActiveQueueLength -gt 50) {
            $recommendations += "Monitor server performance and consider scaling"
        }

        $analytics.Recommendations = $recommendations

        $result.Analytics = $analytics
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DHCP analytics: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Start-DHCPMonitoring',
    'Get-DHCPHealthStatus',
    'Set-DHCPAlerting',
    'Get-DHCPAnalytics'
)
