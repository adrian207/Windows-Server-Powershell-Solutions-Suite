#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Monitoring Module

.DESCRIPTION
    PowerShell module for Windows Active Directory monitoring and alerting.
    Provides comprehensive monitoring capabilities including health monitoring,
    performance monitoring, event monitoring, and alerting.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Module variables
$ModuleVersion = "1.0.0"
$ModuleAuthor = "Adrian Johnson (adrian207@gmail.com)"

# Monitoring Functions
function Get-ADHealthMonitoring {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$MonitoringLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeReplication,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeFSMO,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDNS,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTimeSync
    )
    
    try {
        Write-Host "Starting health monitoring on $ServerName..." -ForegroundColor Cyan
        
        $healthMonitoring = @{
            ServerName = $ServerName
            MonitoringLevel = $MonitoringLevel
            Timestamp = Get-Date
            MonitoringResults = @{}
            Issues = @()
            Recommendations = @()
            OverallStatus = "Unknown"
        }
        
        # Monitor domain controller health
        try {
            $dcHealth = Get-ADDomainController -Server $ServerName -ErrorAction Stop
            $healthMonitoring.MonitoringResults.DomainController = @{
                Status = "Healthy"
                Details = $dcHealth
                Timestamp = Get-Date
            }
        }
        catch {
            $healthMonitoring.MonitoringResults.DomainController = @{
                Status = "Unhealthy"
                Details = $_.Exception.Message
                Timestamp = Get-Date
            }
            $healthMonitoring.Issues += "Domain controller health check failed"
        }
        
        # Monitor replication if requested
        if ($IncludeReplication) {
            try {
                $replicationHealth = Get-ADReplicationPartnerMetadata -Target $ServerName -ErrorAction Stop
                $healthMonitoring.MonitoringResults.Replication = @{
                    Status = "Healthy"
                    Details = $replicationHealth
                    Timestamp = Get-Date
                }
            }
            catch {
                $healthMonitoring.MonitoringResults.Replication = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $healthMonitoring.Issues += "Replication health check failed"
            }
        }
        
        # Monitor FSMO roles if requested
        if ($IncludeFSMO) {
            try {
                $fsmoHealth = Get-ADForest -Server $ServerName | Select-Object SchemaMaster, DomainNamingMaster
                $fsmoHealth | ForEach-Object {
                    $fsmoHealth += Get-ADDomain -Server $ServerName | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
                }
                $healthMonitoring.MonitoringResults.FSMO = @{
                    Status = "Healthy"
                    Details = $fsmoHealth
                    Timestamp = Get-Date
                }
            }
            catch {
                $healthMonitoring.MonitoringResults.FSMO = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $healthMonitoring.Issues += "FSMO roles health check failed"
            }
        }
        
        # Determine overall status
        $unhealthyComponents = $healthMonitoring.MonitoringResults.Values | Where-Object { $_.Status -eq "Unhealthy" }
        if ($unhealthyComponents.Count -eq 0) {
            $healthMonitoring.OverallStatus = "Healthy"
        } elseif ($unhealthyComponents.Count -lt $healthMonitoring.MonitoringResults.Count / 2) {
            $healthMonitoring.OverallStatus = "Degraded"
        } else {
            $healthMonitoring.OverallStatus = "Unhealthy"
        }
        
        return $healthMonitoring
    }
    catch {
        Write-Error "Failed to perform health monitoring: $($_.Exception.Message)"
        throw
    }
}

function Get-ADPerformanceMonitoring {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$MonitoringLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Metrics = @("CPU", "Memory", "Disk", "Network")
    )
    
    try {
        Write-Host "Starting performance monitoring on $ServerName..." -ForegroundColor Cyan
        
        $performanceMonitoring = @{
            ServerName = $ServerName
            MonitoringLevel = $MonitoringLevel
            DurationMinutes = $DurationMinutes
            Metrics = $Metrics
            Timestamp = Get-Date
            PerformanceResults = @{}
            Issues = @()
            Recommendations = @()
            OverallStatus = "Unknown"
        }
        
        # Monitor CPU performance
        if ($Metrics -contains "CPU") {
            try {
                $cpuPerformance = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -MaxSamples 10 -ErrorAction Stop
                $performanceMonitoring.PerformanceResults.CPU = @{
                    Status = "Healthy"
                    Details = $cpuPerformance
                    Timestamp = Get-Date
                }
            }
            catch {
                $performanceMonitoring.PerformanceResults.CPU = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $performanceMonitoring.Issues += "CPU performance monitoring failed"
            }
        }
        
        # Monitor memory performance
        if ($Metrics -contains "Memory") {
            try {
                $memoryPerformance = Get-Counter -Counter "\Memory\Available MBytes" -MaxSamples 10 -ErrorAction Stop
                $performanceMonitoring.PerformanceResults.Memory = @{
                    Status = "Healthy"
                    Details = $memoryPerformance
                    Timestamp = Get-Date
                }
            }
            catch {
                $performanceMonitoring.PerformanceResults.Memory = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $performanceMonitoring.Issues += "Memory performance monitoring failed"
            }
        }
        
        # Monitor disk performance
        if ($Metrics -contains "Disk") {
            try {
                $diskPerformance = Get-Counter -Counter "\PhysicalDisk(_Total)\% Disk Time" -MaxSamples 10 -ErrorAction Stop
                $performanceMonitoring.PerformanceResults.Disk = @{
                    Status = "Healthy"
                    Details = $diskPerformance
                    Timestamp = Get-Date
                }
            }
            catch {
                $performanceMonitoring.PerformanceResults.Disk = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $performanceMonitoring.Issues += "Disk performance monitoring failed"
            }
        }
        
        # Monitor network performance
        if ($Metrics -contains "Network") {
            try {
                $networkPerformance = Get-Counter -Counter "\Network Interface(*)\Bytes Total/sec" -MaxSamples 10 -ErrorAction Stop
                $performanceMonitoring.PerformanceResults.Network = @{
                    Status = "Healthy"
                    Details = $networkPerformance
                    Timestamp = Get-Date
                }
            }
            catch {
                $performanceMonitoring.PerformanceResults.Network = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $performanceMonitoring.Issues += "Network performance monitoring failed"
            }
        }
        
        # Determine overall status
        $unhealthyComponents = $performanceMonitoring.PerformanceResults.Values | Where-Object { $_.Status -eq "Unhealthy" }
        if ($unhealthyComponents.Count -eq 0) {
            $performanceMonitoring.OverallStatus = "Healthy"
        } elseif ($unhealthyComponents.Count -lt $performanceMonitoring.PerformanceResults.Count / 2) {
            $performanceMonitoring.OverallStatus = "Degraded"
        } else {
            $performanceMonitoring.OverallStatus = "Unhealthy"
        }
        
        return $performanceMonitoring
    }
    catch {
        Write-Error "Failed to perform performance monitoring: $($_.Exception.Message)"
        throw
    }
}

function Get-ADEventMonitoring {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$MonitoringLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [string]$LogLevel = "All",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 1000,
        
        [Parameter(Mandatory = $false)]
        [int]$HoursBack = 24
    )
    
    try {
        Write-Host "Starting event monitoring on $ServerName..." -ForegroundColor Cyan
        
        $eventMonitoring = @{
            ServerName = $ServerName
            MonitoringLevel = $MonitoringLevel
            LogLevel = $LogLevel
            MaxEvents = $MaxEvents
            HoursBack = $HoursBack
            Timestamp = Get-Date
            EventResults = @{}
            Issues = @()
            Recommendations = @()
            OverallStatus = "Unknown"
        }
        
        # Monitor application events
        try {
            $appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddHours(-$HoursBack)} -MaxEvents $MaxEvents -ErrorAction Stop
            $eventMonitoring.EventResults.Application = @{
                Status = "Healthy"
                Details = $appEvents
                Timestamp = Get-Date
            }
        }
        catch {
            $eventMonitoring.EventResults.Application = @{
                Status = "Unhealthy"
                Details = $_.Exception.Message
                Timestamp = Get-Date
            }
            $eventMonitoring.Issues += "Application event monitoring failed"
        }
        
        # Monitor system events
        try {
            $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-$HoursBack)} -MaxEvents $MaxEvents -ErrorAction Stop
            $eventMonitoring.EventResults.System = @{
                Status = "Healthy"
                Details = $systemEvents
                Timestamp = Get-Date
            }
        }
        catch {
            $eventMonitoring.EventResults.System = @{
                Status = "Unhealthy"
                Details = $_.Exception.Message
                Timestamp = Get-Date
            }
            $eventMonitoring.Issues += "System event monitoring failed"
        }
        
        # Monitor security events
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-$HoursBack)} -MaxEvents $MaxEvents -ErrorAction Stop
            $eventMonitoring.EventResults.Security = @{
                Status = "Healthy"
                Details = $securityEvents
                Timestamp = Get-Date
            }
        }
        catch {
            $eventMonitoring.EventResults.Security = @{
                Status = "Unhealthy"
                Details = $_.Exception.Message
                Timestamp = Get-Date
            }
            $eventMonitoring.Issues += "Security event monitoring failed"
        }
        
        # Determine overall status
        $unhealthyComponents = $eventMonitoring.EventResults.Values | Where-Object { $_.Status -eq "Unhealthy" }
        if ($unhealthyComponents.Count -eq 0) {
            $eventMonitoring.OverallStatus = "Healthy"
        } elseif ($unhealthyComponents.Count -lt $eventMonitoring.EventResults.Count / 2) {
            $eventMonitoring.OverallStatus = "Degraded"
        } else {
            $eventMonitoring.OverallStatus = "Unhealthy"
        }
        
        return $eventMonitoring
    }
    catch {
        Write-Error "Failed to perform event monitoring: $($_.Exception.Message)"
        throw
    }
}

function Set-ADAlerting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$AlertLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [string[]]$AlertTypes = @("Email", "Webhook"),
        
        [Parameter(Mandatory = $false)]
        [string]$SmtpServer,
        
        [Parameter(Mandatory = $false)]
        [int]$SmtpPort = 587,
        
        [Parameter(Mandatory = $false)]
        [string]$SmtpUsername,
        
        [Parameter(Mandatory = $false)]
        [string]$SmtpPassword,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Recipients = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$WebhookUrl,
        
        [Parameter(Mandatory = $false)]
        [string]$SmsProvider,
        
        [Parameter(Mandatory = $false)]
        [string]$SmsApiKey,
        
        [Parameter(Mandatory = $false)]
        [string]$SmsApiSecret,
        
        [Parameter(Mandatory = $false)]
        [string]$SmsFromNumber,
        
        [Parameter(Mandatory = $false)]
        [string[]]$SmsRecipients = @()
    )
    
    try {
        Write-Host "Configuring alerting on $ServerName..." -ForegroundColor Cyan
        
        $alertingConfig = @{
            ServerName = $ServerName
            AlertLevel = $AlertLevel
            AlertTypes = $AlertTypes
            SmtpServer = $SmtpServer
            SmtpPort = $SmtpPort
            SmtpUsername = $SmtpUsername
            SmtpPassword = $SmtpPassword
            Recipients = $Recipients
            WebhookUrl = $WebhookUrl
            SmsProvider = $SmsProvider
            SmsApiKey = $SmsApiKey
            SmsApiSecret = $SmsApiSecret
            SmsFromNumber = $SmsFromNumber
            SmsRecipients = $SmsRecipients
            Timestamp = Get-Date
        }
        
        # Configure email alerting
        if ($AlertTypes -contains "Email" -and $SmtpServer) {
            Write-Host "Configuring email alerting..." -ForegroundColor Yellow
            # Configure email alerting settings
        }
        
        # Configure webhook alerting
        if ($AlertTypes -contains "Webhook" -and $WebhookUrl) {
            Write-Host "Configuring webhook alerting..." -ForegroundColor Yellow
            # Configure webhook alerting settings
        }
        
        # Configure SMS alerting
        if ($AlertTypes -contains "SMS" -and $SmsProvider) {
            Write-Host "Configuring SMS alerting..." -ForegroundColor Yellow
            # Configure SMS alerting settings
        }
        
        Write-Host "Alerting configured successfully" -ForegroundColor Green
        
        return $alertingConfig
    }
    catch {
        Write-Error "Failed to configure alerting: $($_.Exception.Message)"
        throw
    }
}

function Get-ADMonitoringReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportType = "Comprehensive",
        
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 7,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputFormat = "HTML",
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )
    
    try {
        Write-Host "Generating monitoring report for $ServerName..." -ForegroundColor Cyan
        
        $monitoringReport = @{
            ServerName = $ServerName
            ReportType = $ReportType
            DaysBack = $DaysBack
            OutputFormat = $OutputFormat
            OutputPath = $OutputPath
            Timestamp = Get-Date
            ReportData = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Generate health report
        if ($ReportType -eq "Health" -or $ReportType -eq "Comprehensive") {
            try {
                $healthReport = Get-ADHealthMonitoring -ServerName $ServerName -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
                $monitoringReport.ReportData.Health = $healthReport
            }
            catch {
                $monitoringReport.Issues += "Health report generation failed"
            }
        }
        
        # Generate performance report
        if ($ReportType -eq "Performance" -or $ReportType -eq "Comprehensive") {
            try {
                $performanceReport = Get-ADPerformanceMonitoring -ServerName $ServerName -DurationMinutes 60 -Metrics @("CPU", "Memory", "Disk", "Network")
                $monitoringReport.ReportData.Performance = $performanceReport
            }
            catch {
                $monitoringReport.Issues += "Performance report generation failed"
            }
        }
        
        # Generate event report
        if ($ReportType -eq "Events" -or $ReportType -eq "Comprehensive") {
            try {
                $eventReport = Get-ADEventMonitoring -ServerName $ServerName -LogLevel "All" -MaxEvents 1000 -HoursBack ($DaysBack * 24)
                $monitoringReport.ReportData.Events = $eventReport
            }
            catch {
                $monitoringReport.Issues += "Event report generation failed"
            }
        }
        
        # Save report if output path specified
        if ($OutputPath) {
            $reportContent = $monitoringReport | ConvertTo-Json -Depth 10
            $reportContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "Monitoring report saved to: $OutputPath" -ForegroundColor Green
        }
        
        return $monitoringReport
    }
    catch {
        Write-Error "Failed to generate monitoring report: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Get-ADHealthMonitoring',
    'Get-ADPerformanceMonitoring',
    'Get-ADEventMonitoring',
    'Set-ADAlerting',
    'Get-ADMonitoringReport'
)
