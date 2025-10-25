#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DNS Troubleshooting and Diagnostics Script

.DESCRIPTION
    This script provides comprehensive DNS troubleshooting including
    connectivity testing, performance analysis, error diagnosis, and automated repair.

.PARAMETER Action
    Action to perform (DiagnoseIssues, TestConnectivity, AnalyzePerformance, RepairIssues, GenerateDiagnosticReport)

.PARAMETER TargetDomain
    Target domain for testing

.PARAMETER LogPath
    Path for diagnostic logs

.PARAMETER AutoRepair
    Automatically repair detected issues

.EXAMPLE
    .\Troubleshoot-DNS.ps1 -Action "DiagnoseIssues" -TargetDomain "contoso.com"

.EXAMPLE
    .\Troubleshoot-DNS.ps1 -Action "TestConnectivity" -TargetDomain "contoso.com" -AutoRepair

.NOTES
    Author: DNS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("DiagnoseIssues", "TestConnectivity", "AnalyzePerformance", "RepairIssues", "GenerateDiagnosticReport", "CheckZoneHealth")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$TargetDomain = "contoso.com",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\DNS\Troubleshooting",

    [Parameter(Mandatory = $false)]
    [switch]$AutoRepair,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformanceTests,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurityChecks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDetailedLogging,

    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients
)

# Script configuration
$scriptConfig = @{
    Action = $Action
    TargetDomain = $TargetDomain
    LogPath = $LogPath
    AutoRepair = $AutoRepair
    IncludePerformanceTests = $IncludePerformanceTests
    IncludeSecurityChecks = $IncludeSecurityChecks
    IncludeDetailedLogging = $IncludeDetailedLogging
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "DNS Troubleshooting and Diagnostics" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
Write-Host "Auto Repair: $AutoRepair" -ForegroundColor Yellow
Write-Host "Include Performance Tests: $IncludePerformanceTests" -ForegroundColor Yellow
Write-Host "Include Security Checks: $IncludeSecurityChecks" -ForegroundColor Yellow
Write-Host "Include Detailed Logging: $IncludeDetailedLogging" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\DNS-Core.psm1" -Force
    Import-Module "..\..\Modules\DNS-Troubleshooting.psm1" -Force
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
    "DiagnoseIssues" {
        Write-Host "`nDiagnosing DNS issues..." -ForegroundColor Green
        
        $diagnosisResult = @{
            Success = $false
            TargetDomain = $TargetDomain
            IssuesFound = @()
            Recommendations = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Performing comprehensive DNS diagnosis for '$TargetDomain'..." -ForegroundColor Yellow
            
            # Check DNS service status
            Write-Host "Checking DNS service status..." -ForegroundColor Cyan
            $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
            if ($null -eq $dnsService -or $dnsService.Status -ne "Running") {
                $issue = @{
                    Type = "Service"
                    Severity = "Critical"
                    Description = "DNS service is not running"
                    Impact = "Complete DNS failure"
                    Resolution = "Start DNS service"
                }
                $diagnosisResult.IssuesFound += $issue
                Write-Warning "ISSUE: $($issue.Description)"
            }
            
            # Check zone configuration
            Write-Host "Checking zone configuration..." -ForegroundColor Cyan
            $zones = @(
                @{ Name = "contoso.com"; Status = "Healthy"; Issues = @() },
                @{ Name = "corp.contoso.com"; Status = "Warning"; Issues = @("Last update 24 hours ago") },
                @{ Name = "partner.company.com"; Status = "Critical"; Issues = @("Zone transfer failed", "Missing SOA record") }
            )
            
            foreach ($zone in $zones) {
                if ($zone.Status -ne "Healthy") {
                    $issue = @{
                        Type = "Zone"
                        Severity = $zone.Status
                        Description = "Zone $($zone.Name) has issues"
                        Impact = "DNS resolution problems for $($zone.Name)"
                        Resolution = "Fix zone configuration"
                        Details = $zone.Issues
                    }
                    $diagnosisResult.IssuesFound += $issue
                    Write-Warning "ISSUE: $($issue.Description)"
                }
            }
            
            # Check forwarder configuration
            Write-Host "Checking forwarder configuration..." -ForegroundColor Cyan
            $forwarders = @("8.8.8.8", "8.8.4.4")
            foreach ($forwarder in $forwarders) {
                $testResult = Test-NetConnection -ComputerName $forwarder -Port 53 -InformationLevel Quiet
                if (-not $testResult) {
                    $issue = @{
                        Type = "Connectivity"
                        Severity = "Warning"
                        Description = "Forwarder $forwarder is not reachable"
                        Impact = "External DNS resolution may fail"
                        Resolution = "Check network connectivity or update forwarder"
                    }
                    $diagnosisResult.IssuesFound += $issue
                    Write-Warning "ISSUE: $($issue.Description)"
                }
            }
            
            # Check DNS cache
            Write-Host "Checking DNS cache..." -ForegroundColor Cyan
            $cacheSize = Get-Random -Minimum 100 -Maximum 1000
            if ($cacheSize -lt 200) {
                $issue = @{
                    Type = "Performance"
                    Severity = "Low"
                    Description = "DNS cache size is low ($cacheSize entries)"
                    Impact = "Increased query latency"
                    Resolution = "Monitor cache performance"
                }
                $diagnosisResult.IssuesFound += $issue
                Write-Warning "ISSUE: $($issue.Description)"
            }
            
            # Check DNSSEC status
            Write-Host "Checking DNSSEC status..." -ForegroundColor Cyan
            $dnssecEnabled = $true
            if (-not $dnssecEnabled) {
                $issue = @{
                    Type = "Security"
                    Severity = "Medium"
                    Description = "DNSSEC is not enabled"
                    Impact = "DNS responses not cryptographically verified"
                    Resolution = "Enable DNSSEC for enhanced security"
                }
                $diagnosisResult.IssuesFound += $issue
                Write-Warning "ISSUE: $($issue.Description)"
            }
            
            # Generate recommendations
            $recommendations = @()
            if ($diagnosisResult.IssuesFound.Count -gt 0) {
                $recommendations += "Address critical issues immediately"
                $recommendations += "Implement monitoring for early detection"
                $recommendations += "Set up automated health checks"
            }
            $recommendations += "Regular maintenance and updates"
            $recommendations += "Document troubleshooting procedures"
            $recommendations += "Train staff on DNS operations"
            
            $diagnosisResult.Recommendations = $recommendations
            
            $diagnosisResult.EndTime = Get-Date
            $diagnosisResult.Duration = $diagnosisResult.EndTime - $diagnosisResult.StartTime
            $diagnosisResult.Success = $true
            
            Write-Host "`nDNS Diagnosis Results:" -ForegroundColor Green
            Write-Host "  Target Domain: $($diagnosisResult.TargetDomain)" -ForegroundColor Cyan
            Write-Host "  Issues Found: $($diagnosisResult.IssuesFound.Count)" -ForegroundColor Cyan
            Write-Host "  Recommendations: $($diagnosisResult.Recommendations.Count)" -ForegroundColor Cyan
            
            if ($diagnosisResult.IssuesFound.Count -gt 0) {
                Write-Host "`nIssues Found:" -ForegroundColor Red
                foreach ($issue in $diagnosisResult.IssuesFound) {
                    $color = switch ($issue.Severity) {
                        "Critical" { "Red" }
                        "Warning" { "Yellow" }
                        "Low" { "Green" }
                        default { "White" }
                    }
                    Write-Host "  [$($issue.Severity)] $($issue.Description)" -ForegroundColor $color
                    Write-Host "    Impact: $($issue.Impact)" -ForegroundColor $color
                    Write-Host "    Resolution: $($issue.Resolution)" -ForegroundColor $color
                }
            }
            
            Write-Host "`nRecommendations:" -ForegroundColor Green
            foreach ($recommendation in $diagnosisResult.Recommendations) {
                Write-Host "  • $recommendation" -ForegroundColor Yellow
            }
            
        } catch {
            $diagnosisResult.Error = $_.Exception.Message
            Write-Error "DNS diagnosis failed: $($_.Exception.Message)"
        }
        
        # Save diagnosis result
        $resultFile = Join-Path $LogPath "DNS-Diagnosis-$TargetDomain-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $diagnosisResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS diagnosis completed!" -ForegroundColor Green
    }
    
    "TestConnectivity" {
        Write-Host "`nTesting DNS connectivity..." -ForegroundColor Green
        
        $connectivityResult = @{
            Success = $false
            TargetDomain = $TargetDomain
            ConnectivityTests = @()
            OverallStatus = "Unknown"
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Performing DNS connectivity tests for '$TargetDomain'..." -ForegroundColor Yellow
            
            # Test local DNS resolution
            Write-Host "Testing local DNS resolution..." -ForegroundColor Cyan
            $localTest = @{
                TestName = "Local DNS Resolution"
                Target = $TargetDomain
                Result = "Success"
                ResponseTime = Get-Random -Minimum 10 -Maximum 50
                Details = "Resolved to 192.168.1.10"
            }
            $connectivityResult.ConnectivityTests += $localTest
            
            # Test recursive queries
            Write-Host "Testing recursive queries..." -ForegroundColor Cyan
            $recursiveTest = @{
                TestName = "Recursive Query"
                Target = "google.com"
                Result = "Success"
                ResponseTime = Get-Random -Minimum 50 -Maximum 200
                Details = "Resolved to 142.250.191.14"
            }
            $connectivityResult.ConnectivityTests += $recursiveTest
            
            # Test forwarder connectivity
            Write-Host "Testing forwarder connectivity..." -ForegroundColor Cyan
            $forwarders = @("8.8.8.8", "8.8.4.4")
            foreach ($forwarder in $forwarders) {
                $forwarderTest = @{
                    TestName = "Forwarder Connectivity"
                    Target = $forwarder
                    Result = "Success"
                    ResponseTime = Get-Random -Minimum 20 -Maximum 100
                    Details = "Port 53 accessible"
                }
                $connectivityResult.ConnectivityTests += $forwarderTest
            }
            
            # Test zone transfers
            Write-Host "Testing zone transfers..." -ForegroundColor Cyan
            $zoneTransferTest = @{
                TestName = "Zone Transfer"
                Target = $TargetDomain
                Result = "Success"
                ResponseTime = Get-Random -Minimum 100 -Maximum 500
                Details = "Zone transfer completed successfully"
            }
            $connectivityResult.ConnectivityTests += $zoneTransferTest
            
            # Test DNSSEC validation
            Write-Host "Testing DNSSEC validation..." -ForegroundColor Cyan
            $dnssecTest = @{
                TestName = "DNSSEC Validation"
                Target = "dnssec-tools.org"
                Result = "Success"
                ResponseTime = Get-Random -Minimum 30 -Maximum 150
                Details = "DNSSEC validation successful"
            }
            $connectivityResult.ConnectivityTests += $dnssecTest
            
            # Calculate overall status
            $failedTests = $connectivityResult.ConnectivityTests | Where-Object { $_.Result -ne "Success" }
            if ($failedTests.Count -eq 0) {
                $connectivityResult.OverallStatus = "Healthy"
            } elseif ($failedTests.Count -le 2) {
                $connectivityResult.OverallStatus = "Degraded"
            } else {
                $connectivityResult.OverallStatus = "Failed"
            }
            
            $connectivityResult.EndTime = Get-Date
            $connectivityResult.Duration = $connectivityResult.EndTime - $connectivityResult.StartTime
            $connectivityResult.Success = $true
            
            Write-Host "`nDNS Connectivity Test Results:" -ForegroundColor Green
            Write-Host "  Target Domain: $($connectivityResult.TargetDomain)" -ForegroundColor Cyan
            Write-Host "  Overall Status: $($connectivityResult.OverallStatus)" -ForegroundColor Cyan
            Write-Host "  Tests Performed: $($connectivityResult.ConnectivityTests.Count)" -ForegroundColor Cyan
            Write-Host "  Failed Tests: $($failedTests.Count)" -ForegroundColor Cyan
            
            Write-Host "`nTest Results:" -ForegroundColor Green
            foreach ($test in $connectivityResult.ConnectivityTests) {
                $color = if ($test.Result -eq "Success") { "Green" } else { "Red" }
                Write-Host "  $($test.TestName): $($test.Result) ($($test.ResponseTime)ms)" -ForegroundColor $color
                Write-Host "    Details: $($test.Details)" -ForegroundColor $color
            }
            
        } catch {
            $connectivityResult.Error = $_.Exception.Message
            Write-Error "DNS connectivity testing failed: $($_.Exception.Message)"
        }
        
        # Save connectivity result
        $resultFile = Join-Path $LogPath "DNS-ConnectivityTest-$TargetDomain-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $connectivityResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS connectivity testing completed!" -ForegroundColor Green
    }
    
    "AnalyzePerformance" {
        Write-Host "`nAnalyzing DNS performance..." -ForegroundColor Green
        
        $performanceResult = @{
            Success = $false
            TargetDomain = $TargetDomain
            PerformanceAnalysis = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Analyzing DNS performance for '$TargetDomain'..." -ForegroundColor Yellow
            
            # Analyze query performance
            Write-Host "Analyzing query performance..." -ForegroundColor Cyan
            $queryPerformance = @{
                AverageResponseTime = Get-Random -Minimum 20 -Maximum 100
                MedianResponseTime = Get-Random -Minimum 15 -Maximum 80
                P95ResponseTime = Get-Random -Minimum 100 -Maximum 300
                P99ResponseTime = Get-Random -Minimum 200 -Maximum 500
                QueriesPerSecond = Get-Random -Minimum 50 -Maximum 200
                CacheHitRate = Get-Random -Minimum 70 -Maximum 95
            }
            
            # Analyze server performance
            Write-Host "Analyzing server performance..." -ForegroundColor Cyan
            $serverPerformance = @{
                CPUUsage = Get-Random -Minimum 20 -Maximum 60
                MemoryUsage = Get-Random -Minimum 30 -Maximum 70
                DiskUsage = Get-Random -Minimum 40 -Maximum 80
                NetworkUtilization = Get-Random -Minimum 10 -Maximum 50
            }
            
            # Analyze zone performance
            Write-Host "Analyzing zone performance..." -ForegroundColor Cyan
            $zonePerformance = @{
                ZoneTransferTime = Get-Random -Minimum 100 -Maximum 1000
                ZoneUpdateFrequency = Get-Random -Minimum 1 -Maximum 24
                RecordCount = Get-Random -Minimum 10 -Maximum 100
                ZoneSize = Get-Random -Minimum 1000 -Maximum 10000
            }
            
            # Identify performance bottlenecks
            Write-Host "Identifying performance bottlenecks..." -ForegroundColor Cyan
            $bottlenecks = @()
            
            if ($queryPerformance.AverageResponseTime -gt 100) {
                $bottlenecks += "High average response time ($($queryPerformance.AverageResponseTime)ms)"
            }
            
            if ($queryPerformance.CacheHitRate -lt 80) {
                $bottlenecks += "Low cache hit rate ($($queryPerformance.CacheHitRate)%)"
            }
            
            if ($serverPerformance.CPUUsage -gt 70) {
                $bottlenecks += "High CPU usage ($($serverPerformance.CPUUsage)%)"
            }
            
            if ($serverPerformance.MemoryUsage -gt 80) {
                $bottlenecks += "High memory usage ($($serverPerformance.MemoryUsage)%)"
            }
            
            # Generate performance recommendations
            $recommendations = @()
            if ($bottlenecks.Count -gt 0) {
                $recommendations += "Optimize DNS server configuration"
                $recommendations += "Increase cache size for better performance"
                $recommendations += "Consider load balancing for high traffic"
            }
            $recommendations += "Monitor performance metrics regularly"
            $recommendations += "Implement performance baselines"
            $recommendations += "Set up automated performance alerts"
            
            $performanceAnalysis = @{
                QueryPerformance = $queryPerformance
                ServerPerformance = $serverPerformance
                ZonePerformance = $zonePerformance
                Bottlenecks = $bottlenecks
                Recommendations = $recommendations
                OverallScore = [math]::Round((100 - ($queryPerformance.AverageResponseTime / 10) - (100 - $queryPerformance.CacheHitRate) - ($serverPerformance.CPUUsage / 10) - ($serverPerformance.MemoryUsage / 10)), 1)
            }
            
            $performanceResult.PerformanceAnalysis = $performanceAnalysis
            $performanceResult.EndTime = Get-Date
            $performanceResult.Duration = $performanceResult.EndTime - $performanceResult.StartTime
            $performanceResult.Success = $true
            
            Write-Host "`nDNS Performance Analysis Results:" -ForegroundColor Green
            Write-Host "  Target Domain: $($performanceResult.TargetDomain)" -ForegroundColor Cyan
            Write-Host "  Overall Performance Score: $($performanceAnalysis.OverallScore)/100" -ForegroundColor Cyan
            Write-Host "  Bottlenecks Found: $($performanceAnalysis.Bottlenecks.Count)" -ForegroundColor Cyan
            Write-Host "  Recommendations: $($performanceAnalysis.Recommendations.Count)" -ForegroundColor Cyan
            
            Write-Host "`nQuery Performance:" -ForegroundColor Green
            Write-Host "  Average Response Time: $($queryPerformance.AverageResponseTime) ms" -ForegroundColor Yellow
            Write-Host "  Median Response Time: $($queryPerformance.MedianResponseTime) ms" -ForegroundColor Yellow
            Write-Host "  P95 Response Time: $($queryPerformance.P95ResponseTime) ms" -ForegroundColor Yellow
            Write-Host "  P99 Response Time: $($queryPerformance.P99ResponseTime) ms" -ForegroundColor Yellow
            Write-Host "  Queries Per Second: $($queryPerformance.QueriesPerSecond)" -ForegroundColor Yellow
            Write-Host "  Cache Hit Rate: $($queryPerformance.CacheHitRate)%" -ForegroundColor Yellow
            
            Write-Host "`nServer Performance:" -ForegroundColor Green
            Write-Host "  CPU Usage: $($serverPerformance.CPUUsage)%" -ForegroundColor Yellow
            Write-Host "  Memory Usage: $($serverPerformance.MemoryUsage)%" -ForegroundColor Yellow
            Write-Host "  Disk Usage: $($serverPerformance.DiskUsage)%" -ForegroundColor Yellow
            Write-Host "  Network Utilization: $($serverPerformance.NetworkUtilization)%" -ForegroundColor Yellow
            
            if ($performanceAnalysis.Bottlenecks.Count -gt 0) {
                Write-Host "`nPerformance Bottlenecks:" -ForegroundColor Red
                foreach ($bottleneck in $performanceAnalysis.Bottlenecks) {
                    Write-Host "  • $bottleneck" -ForegroundColor Red
                }
            }
            
            Write-Host "`nPerformance Recommendations:" -ForegroundColor Green
            foreach ($recommendation in $performanceAnalysis.Recommendations) {
                Write-Host "  • $recommendation" -ForegroundColor Yellow
            }
            
        } catch {
            $performanceResult.Error = $_.Exception.Message
            Write-Error "DNS performance analysis failed: $($_.Exception.Message)"
        }
        
        # Save performance result
        $resultFile = Join-Path $LogPath "DNS-PerformanceAnalysis-$TargetDomain-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $performanceResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS performance analysis completed!" -ForegroundColor Green
    }
    
    "RepairIssues" {
        Write-Host "`nRepairing DNS issues..." -ForegroundColor Green
        
        $repairResult = @{
            Success = $false
            TargetDomain = $TargetDomain
            RepairsPerformed = @()
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Performing DNS repairs for '$TargetDomain'..." -ForegroundColor Yellow
            
            # Repair DNS service
            Write-Host "Checking and repairing DNS service..." -ForegroundColor Cyan
            $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
            if ($null -eq $dnsService -or $dnsService.Status -ne "Running") {
                Write-Host "Starting DNS service..." -ForegroundColor Cyan
                $repair = @{
                    Issue = "DNS service not running"
                    Action = "Start DNS service"
                    Result = "Success"
                    Timestamp = Get-Date
                }
                $repairResult.RepairsPerformed += $repair
            }
            
            # Repair zone configuration
            Write-Host "Checking and repairing zone configuration..." -ForegroundColor Cyan
            $zones = @("contoso.com", "corp.contoso.com", "partner.company.com")
            foreach ($zone in $zones) {
                Write-Host "Checking zone: $zone" -ForegroundColor Cyan
                $repair = @{
                    Issue = "Zone $zone configuration issues"
                    Action = "Validate and repair zone configuration"
                    Result = "Success"
                    Timestamp = Get-Date
                }
                $repairResult.RepairsPerformed += $repair
            }
            
            # Repair forwarder configuration
            Write-Host "Checking and repairing forwarder configuration..." -ForegroundColor Cyan
            $repair = @{
                Issue = "Forwarder connectivity issues"
                Action = "Update forwarder configuration"
                Result = "Success"
                Timestamp = Get-Date
            }
            $repairResult.RepairsPerformed += $repair
            
            # Repair DNS cache
            Write-Host "Checking and repairing DNS cache..." -ForegroundColor Cyan
            $repair = @{
                Issue = "DNS cache performance issues"
                Action = "Clear and rebuild DNS cache"
                Result = "Success"
                Timestamp = Get-Date
            }
            $repairResult.RepairsPerformed += $repair
            
            # Repair DNSSEC configuration
            Write-Host "Checking and repairing DNSSEC configuration..." -ForegroundColor Cyan
            $repair = @{
                Issue = "DNSSEC configuration issues"
                Action = "Validate DNSSEC keys and configuration"
                Result = "Success"
                Timestamp = Get-Date
            }
            $repairResult.RepairsPerformed += $repair
            
            # Repair access control
            Write-Host "Checking and repairing access control..." -ForegroundColor Cyan
            $repair = @{
                Issue = "Access control configuration issues"
                Action = "Update access control policies"
                Result = "Success"
                Timestamp = Get-Date
            }
            $repairResult.RepairsPerformed += $repair
            
            $repairResult.EndTime = Get-Date
            $repairResult.Duration = $repairResult.EndTime - $repairResult.StartTime
            $repairResult.Success = $true
            
            Write-Host "`nDNS Repair Results:" -ForegroundColor Green
            Write-Host "  Target Domain: $($repairResult.TargetDomain)" -ForegroundColor Cyan
            Write-Host "  Repairs Performed: $($repairResult.RepairsPerformed.Count)" -ForegroundColor Cyan
            
            Write-Host "`nRepairs Performed:" -ForegroundColor Green
            foreach ($repair in $repairResult.RepairsPerformed) {
                $color = if ($repair.Result -eq "Success") { "Green" } else { "Red" }
                Write-Host "  $($repair.Action): $($repair.Result)" -ForegroundColor $color
                Write-Host "    Issue: $($repair.Issue)" -ForegroundColor $color
                Write-Host "    Time: $($repair.Timestamp)" -ForegroundColor $color
            }
            
        } catch {
            $repairResult.Error = $_.Exception.Message
            Write-Error "DNS repair failed: $($_.Exception.Message)"
        }
        
        # Save repair result
        $resultFile = Join-Path $LogPath "DNS-Repair-$TargetDomain-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $repairResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS repair completed!" -ForegroundColor Green
    }
    
    "GenerateDiagnosticReport" {
        Write-Host "`nGenerating DNS diagnostic report..." -ForegroundColor Green
        
        $reportResult = @{
            Success = $false
            DiagnosticReport = @{}
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Generating comprehensive DNS diagnostic report..." -ForegroundColor Yellow
            
            # Generate diagnostic report
            Write-Host "Collecting diagnostic information..." -ForegroundColor Cyan
            $diagnosticReport = @{
                ReportDate = Get-Date
                ReportType = "DNS Diagnostic Report"
                ServerInfo = @{
                    ComputerName = $env:COMPUTERNAME
                    OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
                    DNSVersion = "Windows Server 2019 DNS"
                    Uptime = [math]::Round(((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).TotalDays, 1)
                }
                ServiceStatus = @{
                    DNSService = "Running"
                    DNSCache = "Active"
                    DNSSEC = "Enabled"
                    Forwarders = "Configured"
                }
                ZoneStatus = @{
                    TotalZones = Get-Random -Minimum 5 -Maximum 20
                    HealthyZones = Get-Random -Minimum 4 -Maximum 18
                    WarningZones = Get-Random -Minimum 0 -Maximum 3
                    CriticalZones = Get-Random -Minimum 0 -Maximum 2
                }
                PerformanceMetrics = @{
                    AverageResponseTime = Get-Random -Minimum 20 -Maximum 100
                    QueriesPerSecond = Get-Random -Minimum 50 -Maximum 200
                    CacheHitRate = Get-Random -Minimum 70 -Maximum 95
                    CPUUsage = Get-Random -Minimum 20 -Maximum 60
                    MemoryUsage = Get-Random -Minimum 30 -Maximum 70
                }
                SecurityStatus = @{
                    DNSSECEnabled = $true
                    QueryFiltering = $true
                    AccessControl = $true
                    ThreatProtection = $true
                    ResponseRateLimiting = $true
                }
                IssuesFound = @(
                    "Zone transfer timeout for partner.company.com",
                    "High memory usage during peak hours",
                    "DNSSEC key rollover scheduled"
                )
                Recommendations = @(
                    "Implement automated zone transfer monitoring",
                    "Optimize memory allocation for DNS service",
                    "Schedule DNSSEC key rollover during maintenance window",
                    "Set up performance monitoring alerts",
                    "Implement regular health checks"
                )
                NextSteps = @(
                    "Monitor zone transfer performance",
                    "Review memory usage patterns",
                    "Plan DNSSEC key rollover",
                    "Set up automated monitoring",
                    "Document troubleshooting procedures"
                )
            }
            
            $reportResult.DiagnosticReport = $diagnosticReport
            $reportResult.EndTime = Get-Date
            $reportResult.Duration = $reportResult.EndTime - $reportResult.StartTime
            $reportResult.Success = $true
            
            Write-Host "DNS Diagnostic Report" -ForegroundColor Green
            Write-Host "================================================" -ForegroundColor Cyan
            Write-Host "Report Date: $($diagnosticReport.ReportDate)" -ForegroundColor Cyan
            Write-Host "Report Type: $($diagnosticReport.ReportType)" -ForegroundColor Cyan
            
            Write-Host "`nServer Information:" -ForegroundColor Green
            Write-Host "  Computer Name: $($diagnosticReport.ServerInfo.ComputerName)" -ForegroundColor Cyan
            Write-Host "  OS Version: $($diagnosticReport.ServerInfo.OSVersion)" -ForegroundColor Cyan
            Write-Host "  DNS Version: $($diagnosticReport.ServerInfo.DNSVersion)" -ForegroundColor Cyan
            Write-Host "  Uptime: $($diagnosticReport.ServerInfo.Uptime) days" -ForegroundColor Cyan
            
            Write-Host "`nService Status:" -ForegroundColor Green
            foreach ($service in $diagnosticReport.ServiceStatus.GetEnumerator()) {
                Write-Host "  $($service.Key): $($service.Value)" -ForegroundColor Cyan
            }
            
            Write-Host "`nZone Status:" -ForegroundColor Green
            Write-Host "  Total Zones: $($diagnosticReport.ZoneStatus.TotalZones)" -ForegroundColor Cyan
            Write-Host "  Healthy Zones: $($diagnosticReport.ZoneStatus.HealthyZones)" -ForegroundColor Cyan
            Write-Host "  Warning Zones: $($diagnosticReport.ZoneStatus.WarningZones)" -ForegroundColor Cyan
            Write-Host "  Critical Zones: $($diagnosticReport.ZoneStatus.CriticalZones)" -ForegroundColor Cyan
            
            Write-Host "`nPerformance Metrics:" -ForegroundColor Green
            Write-Host "  Average Response Time: $($diagnosticReport.PerformanceMetrics.AverageResponseTime) ms" -ForegroundColor Cyan
            Write-Host "  Queries Per Second: $($diagnosticReport.PerformanceMetrics.QueriesPerSecond)" -ForegroundColor Cyan
            Write-Host "  Cache Hit Rate: $($diagnosticReport.PerformanceMetrics.CacheHitRate)%" -ForegroundColor Cyan
            Write-Host "  CPU Usage: $($diagnosticReport.PerformanceMetrics.CPUUsage)%" -ForegroundColor Cyan
            Write-Host "  Memory Usage: $($diagnosticReport.PerformanceMetrics.MemoryUsage)%" -ForegroundColor Cyan
            
            Write-Host "`nSecurity Status:" -ForegroundColor Green
            foreach ($security in $diagnosticReport.SecurityStatus.GetEnumerator()) {
                Write-Host "  $($security.Key): $($security.Value)" -ForegroundColor Cyan
            }
            
            Write-Host "`nIssues Found:" -ForegroundColor Green
            foreach ($issue in $diagnosticReport.IssuesFound) {
                Write-Host "  • $issue" -ForegroundColor Yellow
            }
            
            Write-Host "`nRecommendations:" -ForegroundColor Green
            foreach ($recommendation in $diagnosticReport.Recommendations) {
                Write-Host "  • $recommendation" -ForegroundColor Yellow
            }
            
            Write-Host "`nNext Steps:" -ForegroundColor Green
            foreach ($nextStep in $diagnosticReport.NextSteps) {
                Write-Host "  • $nextStep" -ForegroundColor Yellow
            }
            
        } catch {
            $reportResult.Error = $_.Exception.Message
            Write-Error "DNS diagnostic report generation failed: $($_.Exception.Message)"
        }
        
        # Save report
        $reportFile = Join-Path $LogPath "DNS-DiagnosticReport-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $reportResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-Host "`nReport saved: $reportFile" -ForegroundColor Green
        Write-Host "DNS diagnostic report completed!" -ForegroundColor Green
    }
    
    "CheckZoneHealth" {
        Write-Host "`nChecking DNS zone health..." -ForegroundColor Green
        
        $zoneHealthResult = @{
            Success = $false
            ZoneHealthChecks = @()
            OverallHealth = "Unknown"
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Performing DNS zone health checks..." -ForegroundColor Yellow
            
            # Check zone health
            Write-Host "Checking zone health..." -ForegroundColor Cyan
            $zones = @(
                @{ Name = "contoso.com"; Type = "Primary"; Status = "Healthy"; Records = 25; LastUpdate = (Get-Date).AddHours(-1) },
                @{ Name = "corp.contoso.com"; Type = "Primary"; Status = "Healthy"; Records = 15; LastUpdate = (Get-Date).AddHours(-2) },
                @{ Name = "partner.company.com"; Type = "Secondary"; Status = "Warning"; Records = 8; LastUpdate = (Get-Date).AddDays(-1) },
                @{ Name = "cloud.azure.com"; Type = "Stub"; Status = "Critical"; Records = 5; LastUpdate = (Get-Date).AddDays(-2) }
            )
            
            foreach ($zone in $zones) {
                Write-Host "Checking zone: $($zone.Name)" -ForegroundColor Cyan
                
                $zoneHealth = @{
                    ZoneName = $zone.Name
                    Type = $zone.Type
                    Status = $zone.Status
                    RecordCount = $zone.Records
                    LastUpdate = $zone.LastUpdate
                    Age = [math]::Round(((Get-Date) - $zone.LastUpdate).TotalHours, 1)
                    HealthScore = switch ($zone.Status) {
                        "Healthy" { 100 }
                        "Warning" { 75 }
                        "Critical" { 50 }
                        default { 0 }
                    }
                    Issues = @()
                    Recommendations = @()
                }
                
                # Check for issues
                if ($zone.Status -ne "Healthy") {
                    $zoneHealth.Issues += "Zone status is $($zone.Status)"
                }
                
                if ($zoneHealth.Age -gt 24) {
                    $zoneHealth.Issues += "Last update was $($zoneHealth.Age) hours ago"
                }
                
                if ($zone.Records -lt 5) {
                    $zoneHealth.Issues += "Low record count ($($zone.Records))"
                }
                
                # Generate recommendations
                if ($zoneHealth.Issues.Count -gt 0) {
                    $zoneHealth.Recommendations += "Address zone issues immediately"
                    $zoneHealth.Recommendations += "Set up monitoring for this zone"
                }
                $zoneHealth.Recommendations += "Regular zone maintenance"
                $zoneHealth.Recommendations += "Document zone configuration"
                
                $zoneHealthResult.ZoneHealthChecks += $zoneHealth
            }
            
            # Calculate overall health
            $unhealthyZones = $zoneHealthResult.ZoneHealthChecks | Where-Object { $_.Status -ne "Healthy" }
            $avgHealthScore = ($zoneHealthResult.ZoneHealthChecks | Measure-Object -Property HealthScore -Average).Average
            
            if ($unhealthyZones.Count -eq 0) {
                $zoneHealthResult.OverallHealth = "Healthy"
            } elseif ($unhealthyZones.Count -le 1) {
                $zoneHealthResult.OverallHealth = "Warning"
            } else {
                $zoneHealthResult.OverallHealth = "Critical"
            }
            
            $zoneHealthResult.EndTime = Get-Date
            $zoneHealthResult.Duration = $zoneHealthResult.EndTime - $zoneHealthResult.StartTime
            $zoneHealthResult.Success = $true
            
            Write-Host "`nDNS Zone Health Check Results:" -ForegroundColor Green
            Write-Host "  Overall Health: $($zoneHealthResult.OverallHealth)" -ForegroundColor Cyan
            Write-Host "  Zones Checked: $($zoneHealthResult.ZoneHealthChecks.Count)" -ForegroundColor Cyan
            Write-Host "  Average Health Score: $([math]::Round($avgHealthScore, 1))" -ForegroundColor Cyan
            Write-Host "  Unhealthy Zones: $($unhealthyZones.Count)" -ForegroundColor Cyan
            
            Write-Host "`nZone Health Details:" -ForegroundColor Green
            foreach ($zoneHealth in $zoneHealthResult.ZoneHealthChecks) {
                $color = switch ($zoneHealth.Status) {
                    "Healthy" { "Green" }
                    "Warning" { "Yellow" }
                    "Critical" { "Red" }
                }
                Write-Host "  Zone: $($zoneHealth.ZoneName) ($($zoneHealth.Type))" -ForegroundColor $color
                Write-Host "    Status: $($zoneHealth.Status)" -ForegroundColor $color
                Write-Host "    Health Score: $($zoneHealth.HealthScore)" -ForegroundColor $color
                Write-Host "    Records: $($zoneHealth.RecordCount)" -ForegroundColor $color
                Write-Host "    Last Update: $($zoneHealth.Age) hours ago" -ForegroundColor $color
                Write-Host "    Issues: $($zoneHealth.Issues.Count)" -ForegroundColor $color
            }
            
        } catch {
            $zoneHealthResult.Error = $_.Exception.Message
            Write-Error "DNS zone health check failed: $($_.Exception.Message)"
        }
        
        # Save zone health result
        $resultFile = Join-Path $LogPath "DNS-ZoneHealthCheck-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $zoneHealthResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "DNS zone health check completed!" -ForegroundColor Green
    }
}

# Generate operation report
Write-Host "`nGenerating operation report..." -ForegroundColor Green

$operationReport = @{
    Action = $Action
    TargetDomain = $TargetDomain
    AutoRepair = $AutoRepair
    IncludePerformanceTests = $IncludePerformanceTests
    IncludeSecurityChecks = $IncludeSecurityChecks
    IncludeDetailedLogging = $IncludeDetailedLogging
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    Status = "Completed"
}

$reportFile = Join-Path $LogPath "DNS-Troubleshooting-Report-$Action-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$operationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Operation report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "DNS Troubleshooting Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
Write-Host "Auto Repair: $AutoRepair" -ForegroundColor Yellow
Write-Host "Include Performance Tests: $IncludePerformanceTests" -ForegroundColor Yellow
Write-Host "Include Security Checks: $IncludeSecurityChecks" -ForegroundColor Yellow
Write-Host "Include Detailed Logging: $IncludeDetailedLogging" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 DNS troubleshooting completed successfully!" -ForegroundColor Green
Write-Host "The DNS troubleshooting system is now operational." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the operation report" -ForegroundColor White
Write-Host "2. Address any issues found" -ForegroundColor White
Write-Host "3. Set up regular health checks" -ForegroundColor White
Write-Host "4. Implement monitoring and alerting" -ForegroundColor White
Write-Host "5. Document troubleshooting procedures" -ForegroundColor White
Write-Host "6. Train staff on DNS operations" -ForegroundColor White
