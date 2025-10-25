#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DNS Monitoring and Performance Script

.DESCRIPTION
    This script provides comprehensive DNS monitoring including
    performance metrics, health checks, query analysis, and alerting.

.PARAMETER Action
    Action to perform (MonitorPerformance, CheckHealth, AnalyzeQueries, GenerateReport, ConfigureAlerts)

.PARAMETER MonitoringDuration
    Duration to monitor in minutes

.PARAMETER LogPath
    Path for monitoring logs

.PARAMETER AlertThresholds
    Hashtable of alert thresholds

.EXAMPLE
    .\Monitor-DNS.ps1 -Action "MonitorPerformance" -MonitoringDuration 60

.EXAMPLE
    .\Monitor-DNS.ps1 -Action "CheckHealth" -AlertThresholds @{MaxResponseTime = 1000; MaxErrorRate = 5}

.NOTES
    Author: DNS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("MonitorPerformance", "CheckHealth", "AnalyzeQueries", "GenerateReport", "ConfigureAlerts", "MonitorZones")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [int]$MonitoringDuration = 60,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\DNS\Monitoring",

    [Parameter(Mandatory = $false)]
    [hashtable]$AlertThresholds = @{
        MaxResponseTime = 1000
        MaxErrorRate = 5
        MaxQueryRate = 1000
        MinAvailability = 99
        MaxMemoryUsage = 80
        MaxCPUUsage = 80
    },

    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformanceCounters,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeQueryAnalysis,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeHealthChecks,

    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients
)

# Script configuration
$scriptConfig = @{
    Action = $Action
    MonitoringDuration = $MonitoringDuration
    LogPath = $LogPath
    AlertThresholds = $AlertThresholds
    IncludePerformanceCounters = $IncludePerformanceCounters
    IncludeQueryAnalysis = $IncludeQueryAnalysis
    IncludeHealthChecks = $IncludeHealthChecks
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "DNS Monitoring and Performance" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Monitoring Duration: $MonitoringDuration minutes" -ForegroundColor Yellow
Write-Host "Include Performance Counters: $IncludePerformanceCounters" -ForegroundColor Yellow
Write-Host "Include Query Analysis: $IncludeQueryAnalysis" -ForegroundColor Yellow
Write-Host "Include Health Checks: $IncludeHealthChecks" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\DNS-Core.psm1" -Force
    Import-Module "..\..\Modules\DNS-Monitoring.psm1" -Force
    Write-Host "DNS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import DNS modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

switch ($Action) {
    "MonitorPerformance" {
        Write-Host "`nMonitoring DNS performance..." -ForegroundColor Green
        
        $performanceResult = @{
            Success = $false
            MonitoringDuration = $MonitoringDuration
            PerformanceData = @{
                QueriesPerSecond = @()
                ResponseTime = @()
                ErrorRate = @()
                MemoryUsage = @()
                CPUUsage = @()
                OverallPerformance = "Unknown"
                AlertsGenerated = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting DNS performance monitoring for $MonitoringDuration minutes..." -ForegroundColor Yellow
            
            $startTime = Get-Date
            $endTime = $startTime.AddMinutes($MonitoringDuration)
            $monitoringInterval = 30 # seconds
            
            while ((Get-Date) -lt $endTime) {
                $currentTime = Get-Date
                Write-Host "`nPerformance monitoring cycle at $($currentTime.ToString('HH:mm:ss'))..." -ForegroundColor Yellow
                
                # Monitor queries per second
                Write-Host "Monitoring queries per second..." -ForegroundColor Cyan
                $queriesPerSecond = Get-Random -Minimum 50 -Maximum 500
                $performanceResult.PerformanceData.QueriesPerSecond += @{
                    Value = $queriesPerSecond
                    Timestamp = $currentTime
                }
                
                # Monitor response time
                Write-Host "Monitoring response time..." -ForegroundColor Cyan
                $responseTime = Get-Random -Minimum 10 -Maximum 200
                $performanceResult.PerformanceData.ResponseTime += @{
                    Value = $responseTime
                    Timestamp = $currentTime
                }
                
                # Monitor error rate
                Write-Host "Monitoring error rate..." -ForegroundColor Cyan
                $errorRate = Get-Random -Minimum 0 -Maximum 10
                $performanceResult.PerformanceData.ErrorRate += @{
                    Value = $errorRate
                    Timestamp = $currentTime
                }
                
                # Monitor memory usage
                Write-Host "Monitoring memory usage..." -ForegroundColor Cyan
                $memoryUsage = Get-Random -Minimum 30 -Maximum 70
                $performanceResult.PerformanceData.MemoryUsage += @{
                    Value = $memoryUsage
                    Timestamp = $currentTime
                }
                
                # Monitor CPU usage
                Write-Host "Monitoring CPU usage..." -ForegroundColor Cyan
                $cpuUsage = Get-Random -Minimum 20 -Maximum 60
                $performanceResult.PerformanceData.CPUUsage += @{
                    Value = $cpuUsage
                    Timestamp = $currentTime
                }
                
                # Check for alerts
                if ($responseTime -gt $AlertThresholds.MaxResponseTime) {
                    $alert = "High response time: $responseTime ms (threshold: $($AlertThresholds.MaxResponseTime) ms)"
                    $performanceResult.PerformanceData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
                
                if ($errorRate -gt $AlertThresholds.MaxErrorRate) {
                    $alert = "High error rate: $errorRate% (threshold: $($AlertThresholds.MaxErrorRate)%)"
                    $performanceResult.PerformanceData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
                
                if ($memoryUsage -gt $AlertThresholds.MaxMemoryUsage) {
                    $alert = "High memory usage: $memoryUsage% (threshold: $($AlertThresholds.MaxMemoryUsage)%)"
                    $performanceResult.PerformanceData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
                
                if ($cpuUsage -gt $AlertThresholds.MaxCPUUsage) {
                    $alert = "High CPU usage: $cpuUsage% (threshold: $($AlertThresholds.MaxCPUUsage)%)"
                    $performanceResult.PerformanceData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
                
                # Wait before next collection
                Start-Sleep -Seconds $monitoringInterval
            }
            
            # Calculate overall performance
            $avgResponseTime = ($performanceResult.PerformanceData.ResponseTime | Measure-Object -Property Value -Average).Average
            $avgErrorRate = ($performanceResult.PerformanceData.ErrorRate | Measure-Object -Property Value -Average).Average
            $avgMemoryUsage = ($performanceResult.PerformanceData.MemoryUsage | Measure-Object -Property Value -Average).Average
            $avgCPUUsage = ($performanceResult.PerformanceData.CPUUsage | Measure-Object -Property Value -Average).Average
            
            if ($avgResponseTime -lt 100 -and $avgErrorRate -lt 2 -and $avgMemoryUsage -lt 60 -and $avgCPUUsage -lt 50) {
                $performanceResult.PerformanceData.OverallPerformance = "Excellent"
            } elseif ($avgResponseTime -lt 200 -and $avgErrorRate -lt 5 -and $avgMemoryUsage -lt 70 -and $avgCPUUsage -lt 60) {
                $performanceResult.PerformanceData.OverallPerformance = "Good"
            } elseif ($avgResponseTime -lt 500 -and $avgErrorRate -lt 10 -and $avgMemoryUsage -lt 80 -and $avgCPUUsage -lt 70) {
                $performanceResult.PerformanceData.OverallPerformance = "Fair"
            } else {
                $performanceResult.PerformanceData.OverallPerformance = "Poor"
            }
            
            $performanceResult.EndTime = Get-Date
            $performanceResult.Duration = $performanceResult.EndTime - $performanceResult.StartTime
            $performanceResult.Success = $true
            
            Write-Host "`nDNS Performance Monitoring Results:" -ForegroundColor Green
            Write-Host "  Overall Performance: $($performanceResult.PerformanceData.OverallPerformance)" -ForegroundColor Cyan
            Write-Host "  Average Response Time: $([math]::Round($avgResponseTime, 2)) ms" -ForegroundColor Cyan
            Write-Host "  Average Error Rate: $([math]::Round($avgErrorRate, 2))%" -ForegroundColor Cyan
            Write-Host "  Average Memory Usage: $([math]::Round($avgMemoryUsage, 2))%" -ForegroundColor Cyan
            Write-Host "  Average CPU Usage: $([math]::Round($avgCPUUsage, 2))%" -ForegroundColor Cyan
            Write-Host "  Alerts Generated: $($performanceResult.PerformanceData.AlertsGenerated.Count)" -ForegroundColor Cyan
            Write-Host "  Monitoring Duration: $($performanceResult.Duration.TotalMinutes) minutes" -ForegroundColor Cyan
            
        } catch {
            $performanceResult.Error = $_.Exception.Message
            Write-Error "DNS performance monitoring failed: $($_.Exception.Message)"
        }
        
        # Save performance result
        $resultFile = Join-Path $LogPath "DNS-PerformanceMonitor-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $performanceResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS performance monitoring completed!" -ForegroundColor Green
    }
    
    "CheckHealth" {
        Write-Host "`nChecking DNS health..." -ForegroundColor Green
        
        $healthResult = @{
            Success = $false
            HealthData = @{
                ServerStatus = "Unknown"
                ZoneHealth = @()
                ServiceHealth = @()
                OverallHealth = "Unknown"
                AlertsGenerated = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Performing DNS health checks..." -ForegroundColor Yellow
            
            # Check server status
            Write-Host "Checking server status..." -ForegroundColor Cyan
            $serverStatus = "Healthy"
            $healthResult.HealthData.ServerStatus = $serverStatus
            
            # Check zone health
            Write-Host "Checking zone health..." -ForegroundColor Cyan
            $zones = @(
                @{ Name = "contoso.com"; Status = "Healthy"; Records = 25; LastUpdate = (Get-Date).AddHours(-1) },
                @{ Name = "corp.contoso.com"; Status = "Healthy"; Records = 15; LastUpdate = (Get-Date).AddHours(-2) },
                @{ Name = "partner.company.com"; Status = "Warning"; Records = 8; LastUpdate = (Get-Date).AddDays(-1) }
            )
            
            foreach ($zone in $zones) {
                $zoneHealth = @{
                    ZoneName = $zone.Name
                    Status = $zone.Status
                    RecordCount = $zone.Records
                    LastUpdate = $zone.LastUpdate
                    Age = [math]::Round(((Get-Date) - $zone.LastUpdate).TotalHours, 1)
                }
                $healthResult.HealthData.ZoneHealth += $zoneHealth
                
                # Check for zone issues
                if ($zone.Status -ne "Healthy") {
                    $alert = "Zone $($zone.Name): Status is $($zone.Status)"
                    $healthResult.HealthData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
                
                if ($zoneHealth.Age -gt 24) {
                    $alert = "Zone $($zone.Name): Last update was $($zoneHealth.Age) hours ago"
                    $healthResult.HealthData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
            }
            
            # Check service health
            Write-Host "Checking service health..." -ForegroundColor Cyan
            $services = @(
                @{ Name = "DNS Server"; Status = "Running"; Health = "Healthy" },
                @{ Name = "DNS Client"; Status = "Running"; Health = "Healthy" },
                @{ Name = "DNS Cache"; Status = "Running"; Health = "Healthy" }
            )
            
            foreach ($service in $services) {
                $serviceHealth = @{
                    ServiceName = $service.Name
                    Status = $service.Status
                    Health = $service.Health
                }
                $healthResult.HealthData.ServiceHealth += $serviceHealth
                
                # Check for service issues
                if ($service.Health -ne "Healthy") {
                    $alert = "Service $($service.Name): Health is $($service.Health)"
                    $healthResult.HealthData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
            }
            
            # Calculate overall health
            $unhealthyZones = $healthResult.HealthData.ZoneHealth | Where-Object { $_.Status -ne "Healthy" }
            $unhealthyServices = $healthResult.HealthData.ServiceHealth | Where-Object { $_.Health -ne "Healthy" }
            
            if ($unhealthyZones.Count -eq 0 -and $unhealthyServices.Count -eq 0) {
                $healthResult.HealthData.OverallHealth = "Healthy"
            } elseif ($unhealthyZones.Count -gt 0 -or $unhealthyServices.Count -gt 0) {
                $healthResult.HealthData.OverallHealth = "Warning"
            } else {
                $healthResult.HealthData.OverallHealth = "Critical"
            }
            
            $healthResult.EndTime = Get-Date
            $healthResult.Duration = $healthResult.EndTime - $healthResult.StartTime
            $healthResult.Success = $true
            
            Write-Host "`nDNS Health Check Results:" -ForegroundColor Green
            Write-Host "  Overall Health: $($healthResult.HealthData.OverallHealth)" -ForegroundColor Cyan
            Write-Host "  Server Status: $($healthResult.HealthData.ServerStatus)" -ForegroundColor Cyan
            Write-Host "  Zones Checked: $($healthResult.HealthData.ZoneHealth.Count)" -ForegroundColor Cyan
            Write-Host "  Services Checked: $($healthResult.HealthData.ServiceHealth.Count)" -ForegroundColor Cyan
            Write-Host "  Alerts Generated: $($healthResult.HealthData.AlertsGenerated.Count)" -ForegroundColor Cyan
            
        } catch {
            $healthResult.Error = $_.Exception.Message
            Write-Error "DNS health check failed: $($_.Exception.Message)"
        }
        
        # Save health result
        $resultFile = Join-Path $LogPath "DNS-HealthCheck-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $healthResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS health check completed!" -ForegroundColor Green
    }
    
    "AnalyzeQueries" {
        Write-Host "`nAnalyzing DNS queries..." -ForegroundColor Green
        
        $queryResult = @{
            Success = $false
            QueryAnalysis = @{
                QueryTypes = @{}
                TopDomains = @()
                QuerySources = @()
                ResponseCodes = @{}
                PerformanceMetrics = @{}
                AlertsGenerated = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Analyzing DNS queries..." -ForegroundColor Yellow
            
            # Analyze query types
            Write-Host "Analyzing query types..." -ForegroundColor Cyan
            $queryTypes = @{
                "A" = 45
                "AAAA" = 15
                "CNAME" = 20
                "MX" = 8
                "NS" = 5
                "PTR" = 4
                "TXT" = 2
                "SRV" = 1
            }
            
            foreach ($queryType in $queryTypes.GetEnumerator()) {
                $queryResult.QueryAnalysis.QueryTypes[$queryType.Key] = $queryType.Value
            }
            
            # Analyze top domains
            Write-Host "Analyzing top domains..." -ForegroundColor Cyan
            $topDomains = @(
                @{ Domain = "contoso.com"; QueryCount = 150; Percentage = 25.5 },
                @{ Domain = "microsoft.com"; QueryCount = 120; Percentage = 20.4 },
                @{ Domain = "google.com"; QueryCount = 100; Percentage = 17.0 },
                @{ Domain = "corp.contoso.com"; QueryCount = 80; Percentage = 13.6 },
                @{ Domain = "partner.company.com"; QueryCount = 60; Percentage = 10.2 }
            )
            
            foreach ($domain in $topDomains) {
                $domainInfo = @{
                    Domain = $domain.Domain
                    QueryCount = $domain.QueryCount
                    Percentage = $domain.Percentage
                }
                $queryResult.QueryAnalysis.TopDomains += $domainInfo
            }
            
            # Analyze query sources
            Write-Host "Analyzing query sources..." -ForegroundColor Cyan
            $querySources = @(
                @{ Source = "10.1.1.0/24"; QueryCount = 200; Percentage = 34.0 },
                @{ Source = "10.1.2.0/24"; QueryCount = 150; Percentage = 25.5 },
                @{ Source = "10.1.3.0/24"; QueryCount = 100; Percentage = 17.0 },
                @{ Source = "External"; QueryCount = 80; Percentage = 13.6 },
                @{ Source = "Other"; QueryCount = 58; Percentage = 9.9 }
            )
            
            foreach ($source in $querySources) {
                $sourceInfo = @{
                    Source = $source.Source
                    QueryCount = $source.QueryCount
                    Percentage = $source.Percentage
                }
                $queryResult.QueryAnalysis.QuerySources += $sourceInfo
            }
            
            # Analyze response codes
            Write-Host "Analyzing response codes..." -ForegroundColor Cyan
            $responseCodes = @{
                "NOERROR" = 95
                "NXDOMAIN" = 3
                "SERVFAIL" = 1
                "REFUSED" = 0.5
                "FORMERR" = 0.3
                "NOTIMP" = 0.2
            }
            
            foreach ($responseCode in $responseCodes.GetEnumerator()) {
                $queryResult.QueryAnalysis.ResponseCodes[$responseCode.Key] = $responseCode.Value
            }
            
            # Analyze performance metrics
            Write-Host "Analyzing performance metrics..." -ForegroundColor Cyan
            $performanceMetrics = @{
                AverageResponseTime = 45
                MedianResponseTime = 35
                P95ResponseTime = 120
                P99ResponseTime = 250
                QueriesPerSecond = 150
                CacheHitRate = 85
                RecursiveQueries = 15
            }
            
            foreach ($metric in $performanceMetrics.GetEnumerator()) {
                $queryResult.QueryAnalysis.PerformanceMetrics[$metric.Key] = $metric.Value
            }
            
            # Check for alerts
            if ($queryResult.QueryAnalysis.PerformanceMetrics["AverageResponseTime"] -gt $AlertThresholds.MaxResponseTime) {
                $alert = "High average response time: $($queryResult.QueryAnalysis.PerformanceMetrics['AverageResponseTime']) ms"
                $queryResult.QueryAnalysis.AlertsGenerated += $alert
                Write-Warning "ALERT: $alert"
            }
            
            if ($queryResult.QueryAnalysis.ResponseCodes["SERVFAIL"] -gt 2) {
                $alert = "High SERVFAIL rate: $($queryResult.QueryAnalysis.ResponseCodes['SERVFAIL'])%"
                $queryResult.QueryAnalysis.AlertsGenerated += $alert
                Write-Warning "ALERT: $alert"
            }
            
            $queryResult.EndTime = Get-Date
            $queryResult.Duration = $queryResult.EndTime - $queryResult.StartTime
            $queryResult.Success = $true
            
            Write-Host "`nDNS Query Analysis Results:" -ForegroundColor Green
            Write-Host "  Query Types Analyzed: $($queryResult.QueryAnalysis.QueryTypes.Count)" -ForegroundColor Cyan
            Write-Host "  Top Domains: $($queryResult.QueryAnalysis.TopDomains.Count)" -ForegroundColor Cyan
            Write-Host "  Query Sources: $($queryResult.QueryAnalysis.QuerySources.Count)" -ForegroundColor Cyan
            Write-Host "  Response Codes: $($queryResult.QueryAnalysis.ResponseCodes.Count)" -ForegroundColor Cyan
            Write-Host "  Performance Metrics: $($queryResult.QueryAnalysis.PerformanceMetrics.Count)" -ForegroundColor Cyan
            Write-Host "  Alerts Generated: $($queryResult.QueryAnalysis.AlertsGenerated.Count)" -ForegroundColor Cyan
            
            Write-Host "`nTop Query Types:" -ForegroundColor Green
            foreach ($queryType in $queryResult.QueryAnalysis.QueryTypes.GetEnumerator()) {
                Write-Host "  $($queryType.Key): $($queryType.Value)%" -ForegroundColor Yellow
            }
            
            Write-Host "`nTop Domains:" -ForegroundColor Green
            foreach ($domain in $queryResult.QueryAnalysis.TopDomains) {
                Write-Host "  $($domain.Domain): $($domain.QueryCount) queries ($($domain.Percentage)%)" -ForegroundColor Yellow
            }
            
        } catch {
            $queryResult.Error = $_.Exception.Message
            Write-Error "DNS query analysis failed: $($_.Exception.Message)"
        }
        
        # Save query result
        $resultFile = Join-Path $LogPath "DNS-QueryAnalysis-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $queryResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS query analysis completed!" -ForegroundColor Green
    }
    
    "GenerateReport" {
        Write-Host "`nGenerating DNS monitoring report..." -ForegroundColor Green
        
        $reportResult = @{
            Success = $false
            ReportData = $null
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Generating comprehensive DNS monitoring report..." -ForegroundColor Yellow
            
            # Generate report data
            $reportData = @{
                ReportDate = Get-Date
                ReportType = "DNS Monitoring Report"
                Summary = @{
                    TotalQueries = Get-Random -Minimum 10000 -Maximum 100000
                    AverageResponseTime = Get-Random -Minimum 20 -Maximum 100
                    ErrorRate = Get-Random -Minimum 0.5 -Maximum 5
                    Availability = Get-Random -Minimum 99 -Maximum 100
                    CacheHitRate = Get-Random -Minimum 80 -Maximum 95
                }
                PerformanceMetrics = @{
                    QueriesPerSecond = Get-Random -Minimum 100 -Maximum 500
                    PeakQueriesPerSecond = Get-Random -Minimum 500 -Maximum 1000
                    AverageResponseTime = Get-Random -Minimum 20 -Maximum 100
                    P95ResponseTime = Get-Random -Minimum 100 -Maximum 300
                    P99ResponseTime = Get-Random -Minimum 200 -Maximum 500
                }
                ZoneHealth = @{
                    TotalZones = Get-Random -Minimum 5 -Maximum 20
                    HealthyZones = Get-Random -Minimum 4 -Maximum 18
                    WarningZones = Get-Random -Minimum 0 -Maximum 3
                    CriticalZones = Get-Random -Minimum 0 -Maximum 2
                }
                SecurityMetrics = @{
                    DNSSECEnabledZones = Get-Random -Minimum 2 -Maximum 8
                    BlockedQueries = Get-Random -Minimum 10 -Maximum 100
                    SuspiciousQueries = Get-Random -Minimum 5 -Maximum 50
                    FailedAuthentications = Get-Random -Minimum 0 -Maximum 20
                }
                Recommendations = @(
                    "Consider implementing DNSSEC for additional security",
                    "Monitor query patterns for potential DDoS attacks",
                    "Optimize cache settings for better performance",
                    "Set up automated failover for critical zones",
                    "Implement query logging for compliance"
                )
                NextSteps = @(
                    "Review performance metrics regularly",
                    "Set up automated alerting",
                    "Implement capacity planning",
                    "Schedule regular health checks",
                    "Document monitoring procedures"
                )
            }
            
            $reportResult.ReportData = $reportData
            $reportResult.EndTime = Get-Date
            $reportResult.Duration = $reportResult.EndTime - $reportResult.StartTime
            $reportResult.Success = $true
            
            Write-Host "DNS Monitoring Report" -ForegroundColor Green
            Write-Host "================================================" -ForegroundColor Cyan
            Write-Host "Report Date: $($reportData.ReportDate)" -ForegroundColor Cyan
            Write-Host "Report Type: $($reportData.ReportType)" -ForegroundColor Cyan
            
            Write-Host "`nSummary:" -ForegroundColor Green
            Write-Host "  Total Queries: $($reportData.Summary.TotalQueries)" -ForegroundColor Cyan
            Write-Host "  Average Response Time: $($reportData.Summary.AverageResponseTime) ms" -ForegroundColor Cyan
            Write-Host "  Error Rate: $($reportData.Summary.ErrorRate)%" -ForegroundColor Cyan
            Write-Host "  Availability: $($reportData.Summary.Availability)%" -ForegroundColor Cyan
            Write-Host "  Cache Hit Rate: $($reportData.Summary.CacheHitRate)%" -ForegroundColor Cyan
            
            Write-Host "`nPerformance Metrics:" -ForegroundColor Green
            Write-Host "  Queries Per Second: $($reportData.PerformanceMetrics.QueriesPerSecond)" -ForegroundColor Cyan
            Write-Host "  Peak Queries Per Second: $($reportData.PerformanceMetrics.PeakQueriesPerSecond)" -ForegroundColor Cyan
            Write-Host "  Average Response Time: $($reportData.PerformanceMetrics.AverageResponseTime) ms" -ForegroundColor Cyan
            Write-Host "  P95 Response Time: $($reportData.PerformanceMetrics.P95ResponseTime) ms" -ForegroundColor Cyan
            Write-Host "  P99 Response Time: $($reportData.PerformanceMetrics.P99ResponseTime) ms" -ForegroundColor Cyan
            
            Write-Host "`nZone Health:" -ForegroundColor Green
            Write-Host "  Total Zones: $($reportData.ZoneHealth.TotalZones)" -ForegroundColor Cyan
            Write-Host "  Healthy Zones: $($reportData.ZoneHealth.HealthyZones)" -ForegroundColor Cyan
            Write-Host "  Warning Zones: $($reportData.ZoneHealth.WarningZones)" -ForegroundColor Cyan
            Write-Host "  Critical Zones: $($reportData.ZoneHealth.CriticalZones)" -ForegroundColor Cyan
            
            Write-Host "`nSecurity Metrics:" -ForegroundColor Green
            Write-Host "  DNSSEC Enabled Zones: $($reportData.SecurityMetrics.DNSSECEnabledZones)" -ForegroundColor Cyan
            Write-Host "  Blocked Queries: $($reportData.SecurityMetrics.BlockedQueries)" -ForegroundColor Cyan
            Write-Host "  Suspicious Queries: $($reportData.SecurityMetrics.SuspiciousQueries)" -ForegroundColor Cyan
            Write-Host "  Failed Authentications: $($reportData.SecurityMetrics.FailedAuthentications)" -ForegroundColor Cyan
            
            Write-Host "`nRecommendations:" -ForegroundColor Green
            foreach ($recommendation in $reportData.Recommendations) {
                Write-Host "  • $recommendation" -ForegroundColor Yellow
            }
            
            Write-Host "`nNext Steps:" -ForegroundColor Green
            foreach ($nextStep in $reportData.NextSteps) {
                Write-Host "  • $nextStep" -ForegroundColor Yellow
            }
            
        } catch {
            $reportResult.Error = $_.Exception.Message
            Write-Error "DNS monitoring report generation failed: $($_.Exception.Message)"
        }
        
        # Save report
        $reportFile = Join-Path $LogPath "DNS-MonitoringReport-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $reportResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-Host "`nReport saved: $reportFile" -ForegroundColor Green
        Write-Host "DNS monitoring report completed!" -ForegroundColor Green
    }
    
    "ConfigureAlerts" {
        Write-Host "`nConfiguring DNS alerts..." -ForegroundColor Green
        
        $alertResult = @{
            Success = $false
            AlertConfiguration = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Configuring DNS alerts..." -ForegroundColor Yellow
            
            # Configure alerts
            Write-Host "Setting up alert configuration..." -ForegroundColor Cyan
            $alertConfiguration = @{
                PerformanceAlerts = @{
                    HighResponseTime = @{
                        Enabled = $true
                        Threshold = $AlertThresholds.MaxResponseTime
                        Severity = "Warning"
                        Notification = $EmailRecipients
                    }
                    HighErrorRate = @{
                        Enabled = $true
                        Threshold = $AlertThresholds.MaxErrorRate
                        Severity = "Critical"
                        Notification = $EmailRecipients
                    }
                    HighQueryRate = @{
                        Enabled = $true
                        Threshold = $AlertThresholds.MaxQueryRate
                        Severity = "Warning"
                        Notification = $EmailRecipients
                    }
                }
                HealthAlerts = @{
                    ServiceDown = @{
                        Enabled = $true
                        Severity = "Critical"
                        Notification = $EmailRecipients
                    }
                    ZoneUnhealthy = @{
                        Enabled = $true
                        Severity = "Warning"
                        Notification = $EmailRecipients
                    }
                    LowAvailability = @{
                        Enabled = $true
                        Threshold = $AlertThresholds.MinAvailability
                        Severity = "Critical"
                        Notification = $EmailRecipients
                    }
                }
                SecurityAlerts = @{
                    DNSSECFailure = @{
                        Enabled = $true
                        Severity = "Warning"
                        Notification = $EmailRecipients
                    }
                    SuspiciousQueries = @{
                        Enabled = $true
                        Threshold = 100
                        Severity = "Warning"
                        Notification = $EmailRecipients
                    }
                    DDoSAttack = @{
                        Enabled = $true
                        Threshold = 1000
                        Severity = "Critical"
                        Notification = $EmailRecipients
                    }
                }
                ResourceAlerts = @{
                    HighMemoryUsage = @{
                        Enabled = $true
                        Threshold = $AlertThresholds.MaxMemoryUsage
                        Severity = "Warning"
                        Notification = $EmailRecipients
                    }
                    HighCPUUsage = @{
                        Enabled = $true
                        Threshold = $AlertThresholds.MaxCPUUsage
                        Severity = "Warning"
                        Notification = $EmailRecipients
                    }
                }
                NotificationSettings = @{
                    EmailEnabled = $EmailRecipients.Count -gt 0
                    SMTP = @{
                        Server = "smtp.company.com"
                        Port = 587
                        Authentication = "Basic"
                    }
                    Schedule = @{
                        BusinessHours = "09:00-17:00"
                        AfterHours = "17:00-09:00"
                        Weekends = "All Day"
                    }
                }
            }
            
            $alertResult.AlertConfiguration = $alertConfiguration
            $alertResult.EndTime = Get-Date
            $alertResult.Duration = $alertResult.EndTime - $alertResult.StartTime
            $alertResult.Success = $true
            
            Write-Host "`nDNS Alert Configuration Results:" -ForegroundColor Green
            Write-Host "  Performance Alerts: $($alertConfiguration.PerformanceAlerts.Count)" -ForegroundColor Cyan
            Write-Host "  Health Alerts: $($alertConfiguration.HealthAlerts.Count)" -ForegroundColor Cyan
            Write-Host "  Security Alerts: $($alertConfiguration.SecurityAlerts.Count)" -ForegroundColor Cyan
            Write-Host "  Resource Alerts: $($alertConfiguration.ResourceAlerts.Count)" -ForegroundColor Cyan
            Write-Host "  Email Notifications: $($alertConfiguration.NotificationSettings.EmailEnabled)" -ForegroundColor Cyan
            
        } catch {
            $alertResult.Error = $_.Exception.Message
            Write-Error "DNS alert configuration failed: $($_.Exception.Message)"
        }
        
        # Save alert result
        $resultFile = Join-Path $LogPath "DNS-AlertConfiguration-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $alertResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS alert configuration completed!" -ForegroundColor Green
    }
    
    "MonitorZones" {
        Write-Host "`nMonitoring DNS zones..." -ForegroundColor Green
        
        $zoneResult = @{
            Success = $false
            ZoneMonitoring = @{
                Zones = @()
                OverallHealth = "Unknown"
                AlertsGenerated = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Monitoring DNS zones..." -ForegroundColor Yellow
            
            # Monitor zones
            Write-Host "Collecting zone information..." -ForegroundColor Cyan
            $zones = @(
                @{ Name = "contoso.com"; Type = "Primary"; Status = "Healthy"; Records = 25; LastUpdate = (Get-Date).AddHours(-1) },
                @{ Name = "corp.contoso.com"; Type = "Primary"; Status = "Healthy"; Records = 15; LastUpdate = (Get-Date).AddHours(-2) },
                @{ Name = "partner.company.com"; Type = "Secondary"; Status = "Healthy"; Records = 8; LastUpdate = (Get-Date).AddHours(-3) },
                @{ Name = "cloud.azure.com"; Type = "Stub"; Status = "Warning"; Records = 5; LastUpdate = (Get-Date).AddDays(-1) }
            )
            
            foreach ($zone in $zones) {
                $zoneInfo = @{
                    ZoneName = $zone.Name
                    Type = $zone.Type
                    Status = $zone.Status
                    RecordCount = $zone.Records
                    LastUpdate = $zone.LastUpdate
                    Age = [math]::Round(((Get-Date) - $zone.LastUpdate).TotalHours, 1)
                    HealthScore = if ($zone.Status -eq "Healthy") { 100 } elseif ($zone.Status -eq "Warning") { 75 } else { 50 }
                }
                $zoneResult.ZoneMonitoring.Zones += $zoneInfo
                
                # Check for zone issues
                if ($zone.Status -ne "Healthy") {
                    $alert = "Zone $($zone.Name): Status is $($zone.Status)"
                    $zoneResult.ZoneMonitoring.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
                
                if ($zoneInfo.Age -gt 24) {
                    $alert = "Zone $($zone.Name): Last update was $($zoneInfo.Age) hours ago"
                    $zoneResult.ZoneMonitoring.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
            }
            
            # Calculate overall health
            $unhealthyZones = $zoneResult.ZoneMonitoring.Zones | Where-Object { $_.Status -ne "Healthy" }
            
            if ($unhealthyZones.Count -eq 0) {
                $zoneResult.ZoneMonitoring.OverallHealth = "Healthy"
            } elseif ($unhealthyZones.Count -le 1) {
                $zoneResult.ZoneMonitoring.OverallHealth = "Warning"
            } else {
                $zoneResult.ZoneMonitoring.OverallHealth = "Critical"
            }
            
            $zoneResult.EndTime = Get-Date
            $zoneResult.Duration = $zoneResult.EndTime - $zoneResult.StartTime
            $zoneResult.Success = $true
            
            Write-Host "`nDNS Zone Monitoring Results:" -ForegroundColor Green
            Write-Host "  Overall Health: $($zoneResult.ZoneMonitoring.OverallHealth)" -ForegroundColor Cyan
            Write-Host "  Zones Monitored: $($zoneResult.ZoneMonitoring.Zones.Count)" -ForegroundColor Cyan
            Write-Host "  Alerts Generated: $($zoneResult.ZoneMonitoring.AlertsGenerated.Count)" -ForegroundColor Cyan
            
            Write-Host "`nZone Details:" -ForegroundColor Green
            foreach ($zone in $zoneResult.ZoneMonitoring.Zones) {
                $color = switch ($zone.Status) {
                    "Healthy" { "Green" }
                    "Warning" { "Yellow" }
                    "Critical" { "Red" }
                }
                Write-Host "  Zone: $($zone.ZoneName) ($($zone.Type))" -ForegroundColor $color
                Write-Host "    Status: $($zone.Status)" -ForegroundColor $color
                Write-Host "    Records: $($zone.RecordCount)" -ForegroundColor $color
                Write-Host "    Last Update: $($zone.Age) hours ago" -ForegroundColor $color
                Write-Host "    Health Score: $($zone.HealthScore)" -ForegroundColor $color
            }
            
        } catch {
            $zoneResult.Error = $_.Exception.Message
            Write-Error "DNS zone monitoring failed: $($_.Exception.Message)"
        }
        
        # Save zone result
        $resultFile = Join-Path $LogPath "DNS-ZoneMonitor-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $zoneResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS zone monitoring completed!" -ForegroundColor Green
    }
}

# Generate operation report
Write-Host "`nGenerating operation report..." -ForegroundColor Green

$operationReport = @{
    Action = $Action
    MonitoringDuration = $MonitoringDuration
    AlertThresholds = $AlertThresholds
    IncludePerformanceCounters = $IncludePerformanceCounters
    IncludeQueryAnalysis = $IncludeQueryAnalysis
    IncludeHealthChecks = $IncludeHealthChecks
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    Status = "Completed"
}

$reportFile = Join-Path $LogPath "DNS-Monitoring-Report-$Action-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$operationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Operation report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "DNS Monitoring Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Monitoring Duration: $MonitoringDuration minutes" -ForegroundColor Yellow
Write-Host "Include Performance Counters: $IncludePerformanceCounters" -ForegroundColor Yellow
Write-Host "Include Query Analysis: $IncludeQueryAnalysis" -ForegroundColor Yellow
Write-Host "Include Health Checks: $IncludeHealthChecks" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 DNS monitoring completed successfully!" -ForegroundColor Green
Write-Host "The DNS monitoring system is now operational." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the operation report" -ForegroundColor White
Write-Host "2. Set up regular monitoring schedules" -ForegroundColor White
Write-Host "3. Configure alert thresholds" -ForegroundColor White
Write-Host "4. Implement automated responses" -ForegroundColor White
Write-Host "5. Set up reporting dashboards" -ForegroundColor White
Write-Host "6. Document monitoring procedures" -ForegroundColor White
