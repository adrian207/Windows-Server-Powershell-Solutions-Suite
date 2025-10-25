#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Host Guardian Service (HGS) Monitoring Module

.DESCRIPTION
    Monitoring functions for Host Guardian Service including:
    - Health monitoring and alerting
    - Performance metrics collection
    - Attestation monitoring
    - Security event monitoring
    - Capacity planning

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module variables
# $ModuleName = "HGS-Monitoring"
# $ModuleVersion = "1.0.0"

# Import required modules
Import-Module ServerManager -ErrorAction SilentlyContinue
Import-Module Hyper-V -ErrorAction SilentlyContinue

function Get-HGSHealthStatus {
    <#
    .SYNOPSIS
        Get comprehensive HGS health status

    .DESCRIPTION
        Retrieves comprehensive health status of HGS services and components.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER IncludeDetails
        Include detailed health information

    .EXAMPLE
        Get-HGSHealthStatus -HgsServer "HGS01" -IncludeDetails
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails
    )

    try {
        Write-Host "Retrieving HGS health status..." -ForegroundColor Green

        $healthStatus = @{
            ServerName = $HgsServer
            Timestamp = Get-Date
            OverallHealth = "Healthy"
            Services = @{}
            AttestationService = @{}
            KeyProtectionService = @{}
            Performance = @{}
            Alerts = @()
        }

        # Check HGS services
        $hgsServices = Get-Service | Where-Object { $_.Name -like "*HGS*" }
        foreach ($service in $hgsServices) {
            $healthStatus.Services[$service.Name] = @{
                Status = $service.Status
                StartType = $service.StartType
                LastStartTime = $service.StartTime
            }
        }

        # Check attestation service
        try {
            $attestationInfo = Get-HgsServer
            $healthStatus.AttestationService = @{
                Status = "Running"
                Mode = $attestationInfo.AttestationMode
                AttestedHosts = (Get-HgsAttestationHostGroup).Count
                LastAttestation = Get-Date
            }
        }
        catch {
            $healthStatus.AttestationService = @{
                Status = "Error"
                Error = $_.Exception.Message
            }
        }

        # Check key protection service
        try {
            $keyProtectionInfo = Get-HgsKeyProtectionCertificate
            $healthStatus.KeyProtectionService = @{
                Status = "Running"
                CertificateSubject = $keyProtectionInfo.Subject
                CertificateExpiry = $keyProtectionInfo.NotAfter
                LastKeyRelease = Get-Date
            }
        }
        catch {
            $healthStatus.KeyProtectionService = @{
                Status = "Error"
                Error = $_.Exception.Message
            }
        }

        # Get performance metrics
        $healthStatus.Performance = Get-HGSPerformanceMetrics -HgsServer $HgsServer

        # Check for alerts
        $healthStatus.Alerts = Get-HGSAlerts -HgsServer $HgsServer

        # Determine overall health
        $unhealthyServices = $healthStatus.Services.Values | Where-Object { $_.Status -ne "Running" }
        if ($unhealthyServices.Count -gt 0) {
            $healthStatus.OverallHealth = "Degraded"
        }

        if ($healthStatus.Alerts.Count -gt 0) {
            $criticalAlerts = $healthStatus.Alerts | Where-Object { $_.Severity -eq "Critical" }
            if ($criticalAlerts.Count -gt 0) {
                $healthStatus.OverallHealth = "Critical"
            } elseif ($healthStatus.OverallHealth -eq "Healthy") {
                $healthStatus.OverallHealth = "Warning"
            }
        }

        return $healthStatus
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HGSPerformanceMetrics {
    <#
    .SYNOPSIS
        Get HGS performance metrics

    .DESCRIPTION
        Retrieves performance metrics for HGS services.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER MetricType
        Type of metrics to retrieve

    .EXAMPLE
        Get-HGSPerformanceMetrics -HgsServer "HGS01" -MetricType "All"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "CPU", "Memory", "Network", "Disk", "Attestation")]
        [string]$MetricType = "All"
    )

    try {
        Write-Host "Retrieving HGS performance metrics..." -ForegroundColor Green

        $metrics = @{
            Timestamp = Get-Date
            ServerName = $HgsServer
            CPU = @{}
            Memory = @{}
            Network = @{}
            Disk = @{}
            Attestation = @{}
        }

        # CPU metrics
        if ($MetricType -eq "All" -or $MetricType -eq "CPU") {
            $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1
            $metrics.CPU = @{
                ProcessorTime = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
                ProcessorQueueLength = (Get-Counter "\System\Processor Queue Length").CounterSamples[0].CookedValue
            }
        }

        # Memory metrics
        if ($MetricType -eq "All" -or $MetricType -eq "Memory") {
            $memory = Get-Counter "\Memory\Available MBytes"
            $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB
            $metrics.Memory = @{
                AvailableMB = $memory.CounterSamples[0].CookedValue
                TotalMB = $totalMemory
                UsedPercentage = [math]::Round((($totalMemory - $memory.CounterSamples[0].CookedValue) / $totalMemory) * 100, 2)
            }
        }

        # Network metrics
        if ($MetricType -eq "All" -or $MetricType -eq "Network") {
            $networkCounters = Get-Counter "\Network Interface(*)\Bytes Total/sec"
            $totalBytesPerSec = ($networkCounters.CounterSamples | Measure-Object CookedValue -Sum).Sum
            $metrics.Network = @{
                BytesPerSecond = $totalBytesPerSec
                ActiveConnections = (Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }).Count
            }
        }

        # Disk metrics
        if ($MetricType -eq "All" -or $MetricType -eq "Disk") {
            $diskCounters = Get-Counter "\PhysicalDisk(_Total)\Disk Read Bytes/sec", "\PhysicalDisk(_Total)\Disk Write Bytes/sec"
            $metrics.Disk = @{
                ReadBytesPerSecond = $diskCounters[0].CounterSamples[0].CookedValue
                WriteBytesPerSecond = $diskCounters[1].CounterSamples[0].CookedValue
                FreeSpaceGB = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Measure-Object FreeSpace -Sum).Sum / 1GB
            }
        }

        # Attestation metrics
        if ($MetricType -eq "All" -or $MetricType -eq "Attestation") {
            try {
                $attestationHosts = Get-HgsAttestationHostGroup
                $metrics.Attestation = @{
                    TotalHosts = $attestationHosts.Count
                    AttestedHosts = ($attestationHosts | Where-Object { $_.Status -eq "Attested" }).Count
                    FailedAttestations = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-HostGuardianService-Admin/Operational'; ID=1001} -MaxEvents 100).Count
                    AverageAttestationTime = 0 # Placeholder - would need custom logging
                }
            }
            catch {
                $metrics.Attestation = @{
                    Error = $_.Exception.Message
                }
            }
        }

        return $metrics
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HGSAlerts {
    <#
    .SYNOPSIS
        Get HGS alerts and warnings

    .DESCRIPTION
        Retrieves current alerts and warnings from HGS services.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER Severity
        Alert severity filter

    .PARAMETER TimeRange
        Time range for alerts (hours)

    .EXAMPLE
        Get-HGSAlerts -HgsServer "HGS01" -Severity "Critical" -TimeRange 24
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Critical", "Warning", "Info")]
        [string]$Severity = "All",

        [Parameter(Mandatory = $false)]
        [int]$TimeRange = 24
    )

    try {
        Write-Host "Retrieving HGS alerts..." -ForegroundColor Green

        $alerts = @()
        $startTime = (Get-Date).AddHours(-$TimeRange)

        # Get HGS service alerts
        $hgsEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-HostGuardianService-Admin/Operational'
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        foreach ($logEvent in $hgsEvents) {
            $alertSeverity = switch ($logEvent.LevelDisplayName) {
                "Error" { "Critical" }
                "Warning" { "Warning" }
                "Information" { "Info" }
                default { "Info" }
            }

            if ($Severity -eq "All" -or $alertSeverity -eq $Severity) {
                $alerts += @{
                Id = $logEvent.Id
                Severity = $alertSeverity
                Message = $logEvent.Message
                TimeGenerated = $logEvent.TimeGenerated
                    Source = "HGS Service"
                    Category = $logEvent.TaskDisplayName
                }
            }
        }

        # Get system alerts that might affect HGS
        $systemEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            StartTime = $startTime
            Level = 2,3 # Error and Warning
        } -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like "*HGS*" -or $_.ProviderName -like "*Hyper-V*" }

        foreach ($logEvent in $systemEvents) {
            $alertSeverity = switch ($logEvent.LevelDisplayName) {
                "Error" { "Critical" }
                "Warning" { "Warning" }
                default { "Info" }
            }

            if ($Severity -eq "All" -or $alertSeverity -eq $Severity) {
                $alerts += @{
                Id = $logEvent.Id
                Severity = $alertSeverity
                Message = $logEvent.Message
                TimeGenerated = $logEvent.TimeGenerated
                    Source = "System"
                    Category = $logEvent.TaskDisplayName
                }
            }
        }

        # Sort by time (newest first)
        $alerts = $alerts | Sort-Object TimeGenerated -Descending

        return $alerts
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-HGSMonitoring {
    <#
    .SYNOPSIS
        Configure HGS monitoring settings

    .DESCRIPTION
        Configures monitoring settings for HGS services.

    .PARAMETER MonitoringLevel
        Monitoring level (Basic, Enhanced, Advanced)

    .PARAMETER AlertThresholds
        Alert thresholds for different metrics

    .PARAMETER LogRetention
        Log retention period (days)

    .EXAMPLE
        Set-HGSMonitoring -MonitoringLevel "Advanced" -LogRetention 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Enhanced", "Advanced")]
        [string]$MonitoringLevel = "Enhanced",

        [Parameter(Mandatory = $false)]
        [hashtable]$AlertThresholds = @{},

        [Parameter(Mandatory = $false)]
        [int]$LogRetention = 30
    )

    try {
        Write-Host "Configuring HGS monitoring..." -ForegroundColor Green

        # Set default alert thresholds if not provided
        if ($AlertThresholds.Count -eq 0) {
            $AlertThresholds = @{
                CPUUsage = 80
                MemoryUsage = 85
                DiskUsage = 90
                FailedAttestations = 5
                ResponseTime = 5000
            }
        }

        # Configure monitoring level
        Set-HgsServer -MonitoringLevel $MonitoringLevel

        # Configure alert thresholds
        Set-HgsAttestationPolicy -Policy "MonitoringThresholds" -Enabled $true -Thresholds $AlertThresholds

        # Configure log retention
        Set-HgsServer -LogRetentionDays $LogRetention

        Write-Host "HGS monitoring configured successfully" -ForegroundColor Green

        return @{
            Success = $true
            Message = "Monitoring configured"
            MonitoringLevel = $MonitoringLevel
            AlertThresholds = $AlertThresholds
            LogRetention = $LogRetention
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-HGSAlerting {
    <#
    .SYNOPSIS
        Configure HGS alerting

    .DESCRIPTION
        Configures alerting for HGS services and events.

    .PARAMETER AlertMethods
        Alert methods (Email, SMS, Webhook, SNMP)

    .PARAMETER Recipients
        Alert recipients

    .PARAMETER AlertRules
        Custom alert rules

    .EXAMPLE
        Set-HGSAlerting -AlertMethods @("Email", "Webhook") -Recipients @("admin@contoso.com")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Email", "SMS", "Webhook", "SNMP", "Slack", "Teams")]
        [string[]]$AlertMethods,

        [Parameter(Mandatory = $false)]
        [string[]]$Recipients = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$AlertRules = @{}
    )

    try {
        Write-Host "Configuring HGS alerting..." -ForegroundColor Green

        # Configure alert methods
        foreach ($method in $AlertMethods) {
            switch ($method) {
                "Email" {
                    Set-HgsAttestationPolicy -Policy "EmailAlerts" -Enabled $true -Recipients $Recipients
                }
                "Webhook" {
                    Set-HgsAttestationPolicy -Policy "WebhookAlerts" -Enabled $true -WebhookUrl $Recipients[0]
                }
                "SNMP" {
                    Set-HgsAttestationPolicy -Policy "SNMPAlerts" -Enabled $true -SNMPCommunity "public"
                }
                "Slack" {
                    Set-HgsAttestationPolicy -Policy "SlackAlerts" -Enabled $true -SlackWebhook $Recipients[0]
                }
                "Teams" {
                    Set-HgsAttestationPolicy -Policy "TeamsAlerts" -Enabled $true -TeamsWebhook $Recipients[0]
                }
            }
        }

        # Configure custom alert rules
        if ($AlertRules.Count -gt 0) {
            Set-HgsAttestationPolicy -Policy "CustomAlertRules" -Enabled $true -Rules $AlertRules
        }

        Write-Host "HGS alerting configured successfully" -ForegroundColor Green

        return @{
            Success = $true
            Message = "Alerting configured"
            AlertMethods = $AlertMethods
            Recipients = $Recipients
            AlertRules = $AlertRules
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HGSCapacityPlanning {
    <#
    .SYNOPSIS
        Get HGS capacity planning information

    .DESCRIPTION
        Retrieves capacity planning information for HGS deployment.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER PlanningHorizon
        Planning horizon in months

    .EXAMPLE
        Get-HGSCapacityPlanning -HgsServer "HGS01" -PlanningHorizon 12
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [int]$PlanningHorizon = 12
    )

    try {
        Write-Host "Retrieving HGS capacity planning information..." -ForegroundColor Green

        $capacityInfo = @{
            ServerName = $HgsServer
            Timestamp = Get-Date
            CurrentCapacity = @{}
            ProjectedCapacity = @{}
            Recommendations = @()
        }

        # Get current capacity metrics
        $currentMetrics = Get-HGSPerformanceMetrics -HgsServer $HgsServer
        $capacityInfo.CurrentCapacity = @{
            CPU = $currentMetrics.CPU.ProcessorTime
            Memory = $currentMetrics.Memory.UsedPercentage
            Disk = $currentMetrics.Disk.FreeSpaceGB
            AttestedHosts = $currentMetrics.Attestation.TotalHosts
        }

        # Calculate projected capacity based on growth trends
        $growthRate = 0.1 # 10% monthly growth assumption
        $capacityInfo.ProjectedCapacity = @{
            CPU = [math]::Round($capacityInfo.CurrentCapacity.CPU * (1 + $growthRate * $PlanningHorizon), 2)
            Memory = [math]::Round($capacityInfo.CurrentCapacity.Memory * (1 + $growthRate * $PlanningHorizon), 2)
            AttestedHosts = [math]::Round($capacityInfo.CurrentCapacity.AttestedHosts * (1 + $growthRate * $PlanningHorizon), 0)
        }

        # Generate recommendations
        if ($capacityInfo.CurrentCapacity.CPU -gt 70) {
            $capacityInfo.Recommendations += "Consider CPU upgrade or load balancing"
        }
        if ($capacityInfo.CurrentCapacity.Memory -gt 80) {
            $capacityInfo.Recommendations += "Consider memory upgrade"
        }
        if ($capacityInfo.CurrentCapacity.Disk -lt 50) {
            $capacityInfo.Recommendations += "Consider disk space expansion"
        }
        if ($capacityInfo.CurrentCapacity.AttestedHosts -gt 100) {
            $capacityInfo.Recommendations += "Consider HGS cluster deployment for high availability"
        }

        return $capacityInfo
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-HGSLogging {
    <#
    .SYNOPSIS
        Configure HGS logging

    .DESCRIPTION
        Configures logging settings for HGS services.

    .PARAMETER LogLevel
        Log level (Basic, Detailed, Verbose)

    .PARAMETER LogRetention
        Log retention period (days)

    .PARAMETER LogLocation
        Log file location

    .EXAMPLE
        Set-HGSLogging -LogLevel "Detailed" -LogRetention 30 -LogLocation "C:\Logs\HGS"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Detailed", "Verbose")]
        [string]$LogLevel = "Detailed",

        [Parameter(Mandatory = $false)]
        [int]$LogRetention = 30,

        [Parameter(Mandatory = $false)]
        [string]$LogLocation = "C:\Logs\HGS"
    )

    try {
        Write-Host "Configuring HGS logging..." -ForegroundColor Green

        # Create log directory if it doesn't exist
        if (!(Test-Path $LogLocation)) {
            New-Item -Path $LogLocation -ItemType Directory -Force
        }

        # Configure log level
        Set-HgsServer -LogLevel $LogLevel

        # Configure log retention
        Set-HgsServer -LogRetentionDays $LogRetention

        # Configure log location
        Set-HgsServer -LogLocation $LogLocation

        Write-Host "HGS logging configured successfully" -ForegroundColor Green

        return @{
            Success = $true
            Message = "Logging configured"
            LogLevel = $LogLevel
            LogRetention = $LogRetention
            LogLocation = $LogLocation
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HGSAuditLogs {
    <#
    .SYNOPSIS
        Get HGS audit logs

    .DESCRIPTION
        Retrieves audit logs from HGS services.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER TimeRange
        Time range for logs (hours)

    .PARAMETER LogType
        Type of logs to retrieve

    .EXAMPLE
        Get-HGSAuditLogs -HgsServer "HGS01" -TimeRange 24 -LogType "All"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [int]$TimeRange = 24,

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Attestation", "KeyProtection", "Admin", "Security")]
        [string]$LogType = "All"
    )

    try {
        Write-Host "Retrieving HGS audit logs..." -ForegroundColor Green

        $auditLogs = @()
        $startTime = (Get-Date).AddHours(-$TimeRange)

        # Get HGS audit events
        $logNames = @()
        switch ($LogType) {
            "All" { $logNames = @('Microsoft-Windows-HostGuardianService-Admin/Operational', 'Microsoft-Windows-HostGuardianService-Admin/Audit') }
            "Attestation" { $logNames = @('Microsoft-Windows-HostGuardianService-Admin/Operational') }
            "KeyProtection" { $logNames = @('Microsoft-Windows-HostGuardianService-Admin/Operational') }
            "Admin" { $logNames = @('Microsoft-Windows-HostGuardianService-Admin/Audit') }
            "Security" { $logNames = @('Security') }
        }

        foreach ($logName in $logNames) {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName = $logName
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue

                foreach ($logEvent in $events) {
                    $auditLogs += @{
                        TimeGenerated = $logEvent.TimeGenerated
                        Id = $logEvent.Id
                        Level = $logEvent.LevelDisplayName
                        Message = $logEvent.Message
                        LogName = $logName
                        User = $logEvent.UserId
                        Computer = $logEvent.MachineName
                    }
                }
            }
            catch {
                Write-Warning "Could not retrieve logs from $logName : $($_.Exception.Message)"
            }
        }

        # Sort by time (newest first)
        $auditLogs = $auditLogs | Sort-Object TimeGenerated -Descending

        return $auditLogs
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-HGSDashboard {
    <#
    .SYNOPSIS
        Configure HGS dashboard

    .DESCRIPTION
        Configures dashboard settings for HGS monitoring.

    .PARAMETER DashboardType
        Dashboard type (Web, PowerShell, Custom)

    .PARAMETER RefreshInterval
        Dashboard refresh interval (seconds)

    .PARAMETER CustomMetrics
        Custom metrics to display

    .EXAMPLE
        Set-HGSDashboard -DashboardType "Web" -RefreshInterval 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Web", "PowerShell", "Custom")]
        [string]$DashboardType = "PowerShell",

        [Parameter(Mandatory = $false)]
        [int]$RefreshInterval = 30,

        [Parameter(Mandatory = $false)]
        [string[]]$CustomMetrics = @()
    )

    try {
        Write-Host "Configuring HGS dashboard..." -ForegroundColor Green

        # Configure dashboard type
        Set-HgsServer -DashboardType $DashboardType

        # Configure refresh interval
        Set-HgsAttestationPolicy -Policy "DashboardRefresh" -Enabled $true -RefreshInterval $RefreshInterval

        # Configure custom metrics
        if ($CustomMetrics.Count -gt 0) {
            Set-HgsAttestationPolicy -Policy "CustomMetrics" -Enabled $true -Metrics $CustomMetrics
        }

        Write-Host "HGS dashboard configured successfully" -ForegroundColor Green

        return @{
            Success = $true
            Message = "Dashboard configured"
            DashboardType = $DashboardType
            RefreshInterval = $RefreshInterval
            CustomMetrics = $CustomMetrics
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HGSReport {
    <#
    .SYNOPSIS
        Generate HGS report

    .DESCRIPTION
        Generates comprehensive HGS report with health, performance, and security information.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER ReportType
        Type of report (Health, Performance, Security, Comprehensive)

    .PARAMETER OutputPath
        Output path for the report

    .EXAMPLE
        Get-HGSReport -HgsServer "HGS01" -ReportType "Comprehensive" -OutputPath "C:\Reports\HGS-Report.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Health", "Performance", "Security", "Comprehensive")]
        [string]$ReportType = "Comprehensive",

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Reports\HGS-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )

    try {
        Write-Host "Generating HGS report..." -ForegroundColor Green

        # Create output directory if it doesn't exist
        $outputDir = Split-Path $OutputPath -Parent
        if (!(Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force
        }

        $report = @{
            GeneratedAt = Get-Date
            ServerName = $HgsServer
            ReportType = $ReportType
            Health = @{}
            Performance = @{}
            Security = @{}
            Alerts = @()
            Recommendations = @()
        }

        # Generate report sections based on type
        if ($ReportType -eq "Health" -or $ReportType -eq "Comprehensive") {
            $report.Health = Get-HGSHealthStatus -HgsServer $HgsServer
        }

        if ($ReportType -eq "Performance" -or $ReportType -eq "Comprehensive") {
            $report.Performance = Get-HGSPerformanceMetrics -HgsServer $HgsServer
        }

        if ($ReportType -eq "Security" -or $ReportType -eq "Comprehensive") {
            $report.Security = Get-HGSAuditLogs -HgsServer $HgsServer -TimeRange 24
        }

        if ($ReportType -eq "Comprehensive") {
            $report.Alerts = Get-HGSAlerts -HgsServer $HgsServer
            $report.CapacityPlanning = Get-HGSCapacityPlanning -HgsServer $HgsServer
        }

        # Generate recommendations
        if ($report.Health.OverallHealth -ne "Healthy") {
            $report.Recommendations += "Review HGS service health and resolve any issues"
        }
        if ($report.Performance.CPU.ProcessorTime -gt 80) {
            $report.Recommendations += "Consider CPU optimization or scaling"
        }
        if ($report.Alerts.Count -gt 0) {
            $report.Recommendations += "Review and address active alerts"
        }

        # Save report to file
        $reportJson = $report | ConvertTo-Json -Depth 10
        $reportJson | Out-File -FilePath $OutputPath -Encoding UTF8

        Write-Host "HGS report generated successfully: $OutputPath" -ForegroundColor Green

        return @{
            Success = $true
            Message = "Report generated"
            OutputPath = $OutputPath
            Report = $report
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Export all functions
Export-ModuleMember -Function *
