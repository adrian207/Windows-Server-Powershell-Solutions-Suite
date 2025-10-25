#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Host Guardian Service (HGS) Troubleshooting Module

.DESCRIPTION
    Troubleshooting functions for Host Guardian Service including:
    - Diagnostic tools and health checks
    - Event log analysis
    - Performance troubleshooting
    - Configuration validation
    - Repair and recovery operations

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module variables
# $ModuleName = "HGS-Troubleshooting"
# $ModuleVersion = "1.0.0"

# Import required modules
Import-Module ServerManager -ErrorAction SilentlyContinue
Import-Module Hyper-V -ErrorAction SilentlyContinue

function Test-HGSDiagnostics {
    <#
    .SYNOPSIS
        Run comprehensive HGS diagnostics

    .DESCRIPTION
        Runs comprehensive diagnostics on HGS services and configuration.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER DiagnosticLevel
        Diagnostic level (Basic, Comprehensive, Deep)

    .PARAMETER IncludePerformance
        Include performance diagnostics

    .EXAMPLE
        Test-HGSDiagnostics -HgsServer "HGS01" -DiagnosticLevel "Comprehensive" -IncludePerformance
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Comprehensive", "Deep")]
        [string]$DiagnosticLevel = "Comprehensive",

        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformance
    )

    try {
        Write-Host "Running HGS diagnostics..." -ForegroundColor Green

        $diagnostics = @{
            ServerName = $HgsServer
            Timestamp = Get-Date
            DiagnosticLevel = $DiagnosticLevel
            Results = @{}
            Issues = @()
            Recommendations = @()
        }

        # Service health check
        Write-Host "Checking HGS services..." -ForegroundColor Yellow
        $hgsServices = Get-Service | Where-Object { $_.Name -like "*HGS*" }
        $serviceResults = @{}
        foreach ($service in $hgsServices) {
            $serviceResults[$service.Name] = @{
                Status = $service.Status
                StartType = $service.StartType
                IsHealthy = $service.Status -eq "Running"
            }
            if ($service.Status -ne "Running") {
                $diagnostics.Issues += "Service $($service.Name) is not running"
                $diagnostics.Recommendations += "Start service $($service.Name)"
            }
        }
        $diagnostics.Results.Services = $serviceResults

        # Configuration validation
        Write-Host "Validating HGS configuration..." -ForegroundColor Yellow
        try {
            $hgsConfig = Get-HgsServer
            $diagnostics.Results.Configuration = @{
                IsValid = $true
                AttestationService = $hgsConfig.AttestationService
                KeyProtectionService = $hgsConfig.KeyProtectionService
                AttestationMode = $hgsConfig.AttestationMode
            }
        }
        catch {
            $diagnostics.Results.Configuration = @{
                IsValid = $false
                Error = $_.Exception.Message
            }
            $diagnostics.Issues += "HGS configuration is invalid"
            $diagnostics.Recommendations += "Review and fix HGS configuration"
        }

        # Certificate validation
        Write-Host "Validating certificates..." -ForegroundColor Yellow
        try {
            $certificates = Get-HgsKeyProtectionCertificate
            $certResults = @{}
            foreach ($cert in $certificates) {
                $isExpired = $cert.NotAfter -lt (Get-Date)
                $isExpiringSoon = $cert.NotAfter -lt (Get-Date).AddDays(30)
                $certResults[$cert.Subject] = @{
                    IsValid = !$isExpired
                    IsExpiringSoon = $isExpiringSoon
                    ExpiryDate = $cert.NotAfter
                }
                if ($isExpired) {
                    $diagnostics.Issues += "Certificate $($cert.Subject) has expired"
                    $diagnostics.Recommendations += "Renew expired certificate"
                }
                if ($isExpiringSoon) {
                    $diagnostics.Issues += "Certificate $($cert.Subject) expires soon"
                    $diagnostics.Recommendations += "Plan certificate renewal"
                }
            }
            $diagnostics.Results.Certificates = $certResults
        }
        catch {
            $diagnostics.Results.Certificates = @{
                Error = $_.Exception.Message
            }
            $diagnostics.Issues += "Certificate validation failed"
            $diagnostics.Recommendations += "Check certificate configuration"
        }

        # Network connectivity check
        Write-Host "Checking network connectivity..." -ForegroundColor Yellow
        $networkResults = @{
            LocalConnectivity = $true
            RemoteConnectivity = @{}
        }
        
        # Test local ports
        $hgsPorts = @(443, 80, 8080)
        foreach ($port in $hgsPorts) {
            try {
                $connection = Test-NetConnection -ComputerName $HgsServer -Port $port -InformationLevel Quiet
                $networkResults.RemoteConnectivity["Port$port"] = $connection
                if (!$connection) {
                    $diagnostics.Issues += "Port $port is not accessible"
                    $diagnostics.Recommendations += "Check firewall rules for port $port"
                }
            }
            catch {
                $networkResults.RemoteConnectivity["Port$port"] = $false
            }
        }
        $diagnostics.Results.Network = $networkResults

        # Event log analysis
        Write-Host "Analyzing event logs..." -ForegroundColor Yellow
        $eventResults = @{
            Errors = 0
            Warnings = 0
            CriticalEvents = @()
        }
        
        try {
            $hgsEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-HostGuardianService-Admin/Operational'
                StartTime = (Get-Date).AddDays(-7)
            } -ErrorAction SilentlyContinue

            foreach ($logEvent in $hgsEvents) {
                switch ($logEvent.LevelDisplayName) {
                    "Error" { 
                        $eventResults.Errors++
                        if ($logEvent.Id -in @(1001, 1002, 1003)) {
                            $eventResults.CriticalEvents += $logEvent
                        }
                    }
                    "Warning" { $eventResults.Warnings++ }
                }
            }
        }
        catch {
            $eventResults.Error = $_.Exception.Message
        }
        $diagnostics.Results.Events = $eventResults

        if ($eventResults.Errors -gt 10) {
            $diagnostics.Issues += "High number of errors in event logs"
            $diagnostics.Recommendations += "Review event logs for recurring issues"
        }

        # Performance diagnostics
        if ($IncludePerformance) {
            Write-Host "Running performance diagnostics..." -ForegroundColor Yellow
            $perfResults = @{
                CPU = (Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue
                Memory = (Get-Counter "\Memory\Available MBytes").CounterSamples[0].CookedValue
                DiskQueue = (Get-Counter "\PhysicalDisk(_Total)\Current Disk Queue Length").CounterSamples[0].CookedValue
            }
            
            if ($perfResults.CPU -gt 90) {
                $diagnostics.Issues += "High CPU usage detected"
                $diagnostics.Recommendations += "Investigate CPU-intensive processes"
            }
            if ($perfResults.Memory -lt 1000) {
                $diagnostics.Issues += "Low available memory"
                $diagnostics.Recommendations += "Consider memory upgrade or optimization"
            }
            if ($perfResults.DiskQueue -gt 5) {
                $diagnostics.Issues += "High disk queue length"
                $diagnostics.Recommendations += "Check disk performance and consider SSD upgrade"
            }
            
            $diagnostics.Results.Performance = $perfResults
        }

        # Attestation diagnostics
        Write-Host "Checking attestation status..." -ForegroundColor Yellow
        try {
            $attestationHosts = Get-HgsAttestationHostGroup
            $attestationResults = @{
                TotalHosts = $attestationHosts.Count
                AttestedHosts = ($attestationHosts | Where-Object { $_.Status -eq "Attested" }).Count
                FailedHosts = ($attestationHosts | Where-Object { $_.Status -eq "Failed" }).Count
            }
            
            if ($attestationResults.FailedHosts -gt 0) {
                $diagnostics.Issues += "$($attestationResults.FailedHosts) hosts failed attestation"
                $diagnostics.Recommendations += "Review failed attestation hosts"
            }
            
            $diagnostics.Results.Attestation = $attestationResults
        }
        catch {
            $diagnostics.Results.Attestation = @{
                Error = $_.Exception.Message
            }
            $diagnostics.Issues += "Attestation check failed"
            $diagnostics.Recommendations += "Verify attestation service configuration"
        }

        # Overall health assessment
        $diagnostics.OverallHealth = if ($diagnostics.Issues.Count -eq 0) { "Healthy" } 
                                   elseif ($diagnostics.Issues.Count -le 3) { "Warning" } 
                                   else { "Critical" }

        Write-Host "HGS diagnostics completed. Overall health: $($diagnostics.OverallHealth)" -ForegroundColor Green

        return $diagnostics
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Repair-HGSService {
    <#
    .SYNOPSIS
        Repair HGS service issues

    .DESCRIPTION
        Attempts to repair common HGS service issues.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER RepairType
        Type of repair to perform

    .PARAMETER Force
        Force repair operations

    .EXAMPLE
        Repair-HGSService -HgsServer "HGS01" -RepairType "All" -Force
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Services", "Configuration", "Certificates", "Network")]
        [string]$RepairType = "All",

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        Write-Host "Starting HGS service repair..." -ForegroundColor Green

        $repairResults = @{
            ServerName = $HgsServer
            Timestamp = Get-Date
            RepairType = $RepairType
            Actions = @()
            Success = $true
        }

        # Repair services
        if ($RepairType -eq "All" -or $RepairType -eq "Services") {
            Write-Host "Repairing HGS services..." -ForegroundColor Yellow
            $hgsServices = Get-Service | Where-Object { $_.Name -like "*HGS*" }
            foreach ($service in $hgsServices) {
                if ($service.Status -ne "Running") {
                    try {
                        Start-Service -Name $service.Name -Force
                        $repairResults.Actions += "Started service $($service.Name)"
                        Write-Host "Started service $($service.Name)" -ForegroundColor Green
                    }
                    catch {
                        $repairResults.Actions += "Failed to start service $($service.Name): $($_.Exception.Message)"
                        $repairResults.Success = $false
                        Write-Warning "Failed to start service $($service.Name): $($_.Exception.Message)"
                    }
                }
            }
        }

        # Repair configuration
        if ($RepairType -eq "All" -or $RepairType -eq "Configuration") {
            Write-Host "Repairing HGS configuration..." -ForegroundColor Yellow
            try {
                # Reset HGS configuration to defaults
                if ($Force) {
                    Initialize-HgsServer -HgsServiceName "HGS" -Force
                    $repairResults.Actions += "Reset HGS configuration to defaults"
                    Write-Host "Reset HGS configuration" -ForegroundColor Green
                }
            }
            catch {
                $repairResults.Actions += "Failed to repair configuration: $($_.Exception.Message)"
                $repairResults.Success = $false
                Write-Warning "Failed to repair configuration: $($_.Exception.Message)"
            }
        }

        # Repair certificates
        if ($RepairType -eq "All" -or $RepairType -eq "Certificates") {
            Write-Host "Repairing certificates..." -ForegroundColor Yellow
            try {
                $certificates = Get-HgsKeyProtectionCertificate
                foreach ($cert in $certificates) {
                    if ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
                        # Generate new certificate
                        $newCert = New-SelfSignedCertificate -Subject "CN=HGS-Repaired-$(Get-Date -Format 'yyyyMMdd')" -CertStoreLocation "Cert:\LocalMachine\My"
                        Set-HgsKeyProtectionCertificate -Thumbprint $newCert.Thumbprint
                        $repairResults.Actions += "Generated new certificate for $($cert.Subject)"
                        Write-Host "Generated new certificate" -ForegroundColor Green
                    }
                }
            }
            catch {
                $repairResults.Actions += "Failed to repair certificates: $($_.Exception.Message)"
                $repairResults.Success = $false
                Write-Warning "Failed to repair certificates: $($_.Exception.Message)"
            }
        }

        # Repair network
        if ($RepairType -eq "All" -or $RepairType -eq "Network") {
            Write-Host "Repairing network configuration..." -ForegroundColor Yellow
            try {
                # Reset network adapters
                $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Disconnected" }
                foreach ($adapter in $adapters) {
                    Enable-NetAdapter -Name $adapter.Name -Confirm:$false
                    $repairResults.Actions += "Enabled network adapter $($adapter.Name)"
                }
                
                # Flush DNS cache
                Clear-DnsClientCache
                $repairResults.Actions += "Flushed DNS cache"
                
                Write-Host "Network configuration repaired" -ForegroundColor Green
            }
            catch {
                $repairResults.Actions += "Failed to repair network: $($_.Exception.Message)"
                $repairResults.Success = $false
                Write-Warning "Failed to repair network: $($_.Exception.Message)"
            }
        }

        Write-Host "HGS service repair completed" -ForegroundColor Green
        return $repairResults
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HGSEventAnalysis {
    <#
    .SYNOPSIS
        Analyze HGS event logs

    .DESCRIPTION
        Analyzes HGS event logs for common issues and patterns.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER TimeRange
        Time range for analysis (days)

    .PARAMETER AnalysisType
        Type of analysis to perform

    .EXAMPLE
        Get-HGSEventAnalysis -HgsServer "HGS01" -TimeRange 7 -AnalysisType "Comprehensive"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [int]$TimeRange = 7,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Comprehensive", "Deep")]
        [string]$AnalysisType = "Comprehensive"
    )

    try {
        Write-Host "Analyzing HGS event logs..." -ForegroundColor Green

        $analysis = @{
            ServerName = $HgsServer
            Timestamp = Get-Date
            TimeRange = $TimeRange
            AnalysisType = $AnalysisType
            EventSummary = @{}
            Patterns = @()
            Issues = @()
            Recommendations = @()
        }

        $startTime = (Get-Date).AddDays(-$TimeRange)

        # Get HGS events
        $hgsEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-HostGuardianService-Admin/Operational'
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        # Event summary
        $analysis.EventSummary = @{
            TotalEvents = $hgsEvents.Count
            Errors = ($hgsEvents | Where-Object { $_.LevelDisplayName -eq "Error" }).Count
            Warnings = ($hgsEvents | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count
            Information = ($hgsEvents | Where-Object { $_.LevelDisplayName -eq "Information" }).Count
        }

        # Pattern analysis
        $eventIds = $hgsEvents | Group-Object Id
        foreach ($eventGroup in $eventIds) {
            if ($eventGroup.Count -gt 5) {
                $analysis.Patterns += @{
                    EventId = $eventGroup.Name
                    Count = $eventGroup.Count
                    Frequency = [math]::Round($eventGroup.Count / $TimeRange, 2)
                    Severity = if ($eventGroup.Name -in @(1001, 1002, 1003)) { "Critical" } else { "Warning" }
                }
            }
        }

        # Issue detection
        $criticalEvents = $hgsEvents | Where-Object { $_.Id -in @(1001, 1002, 1003) }
        if ($criticalEvents.Count -gt 0) {
            $analysis.Issues += "Critical HGS events detected"
            $analysis.Recommendations += "Investigate critical events immediately"
        }

        $errorEvents = $hgsEvents | Where-Object { $_.LevelDisplayName -eq "Error" }
        if ($errorEvents.Count -gt 10) {
            $analysis.Issues += "High number of error events"
            $analysis.Recommendations += "Review error patterns and root causes"
        }

        # Time-based analysis
        $hourlyEvents = $hgsEvents | Group-Object { $_.TimeGenerated.Hour }
        $peakHours = $hourlyEvents | Sort-Object Count -Descending | Select-Object -First 3
        if ($peakHours.Count -gt 0) {
            $analysis.Patterns += @{
                Type = "Peak Hours"
                Hours = $peakHours.Name
                Counts = $peakHours.Count
            }
        }

        # Deep analysis
        if ($AnalysisType -eq "Deep") {
            Write-Host "Performing deep analysis..." -ForegroundColor Yellow
            
            # Analyze event correlation
            $correlatedEvents = @()
            $eventGroups = $hgsEvents | Group-Object { $_.TimeGenerated.ToString("yyyy-MM-dd HH") }
            foreach ($group in $eventGroups) {
                if ($group.Count -gt 10) {
                    $correlatedEvents += @{
                        TimeWindow = $group.Name
                        EventCount = $group.Count
                        EventIds = $group.Group.Id | Sort-Object -Unique
                    }
                }
            }
            $analysis.CorrelatedEvents = $correlatedEvents
        }

        Write-Host "Event analysis completed" -ForegroundColor Green
        return $analysis
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-HGSConfiguration {
    <#
    .SYNOPSIS
        Test HGS configuration validity

    .DESCRIPTION
        Tests the validity of HGS configuration and settings.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER TestType
        Type of configuration test

    .EXAMPLE
        Test-HGSConfiguration -HgsServer "HGS01" -TestType "All"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Basic", "Security", "Performance")]
        [string]$TestType = "All"
    )

    try {
        Write-Host "Testing HGS configuration..." -ForegroundColor Green

        $testResults = @{
            ServerName = $HgsServer
            Timestamp = Get-Date
            TestType = $TestType
            Tests = @{}
            OverallResult = "Pass"
            Issues = @()
        }

        # Basic configuration test
        if ($TestType -eq "All" -or $TestType -eq "Basic") {
            Write-Host "Running basic configuration tests..." -ForegroundColor Yellow
            
            try {
                $hgsConfig = Get-HgsServer
                $testResults.Tests.BasicConfig = @{
                    Result = "Pass"
                    AttestationService = $hgsConfig.AttestationService
                    KeyProtectionService = $hgsConfig.KeyProtectionService
                    AttestationMode = $hgsConfig.AttestationMode
                }
            }
            catch {
                $testResults.Tests.BasicConfig = @{
                    Result = "Fail"
                    Error = $_.Exception.Message
                }
                $testResults.Issues += "Basic configuration test failed"
                $testResults.OverallResult = "Fail"
            }
        }

        # Security configuration test
        if ($TestType -eq "All" -or $TestType -eq "Security") {
            Write-Host "Running security configuration tests..." -ForegroundColor Yellow
            
            $securityTests = @{
                Certificates = @{}
                AttestationPolicies = @{}
                AccessControl = @{}
            }

            # Test certificates
            try {
                $certificates = Get-HgsKeyProtectionCertificate
                $securityTests.Certificates = @{
                    Result = "Pass"
                    Count = $certificates.Count
                    ExpiryDates = $certificates.NotAfter
                }
            }
            catch {
                $securityTests.Certificates = @{
                    Result = "Fail"
                    Error = $_.Exception.Message
                }
                $testResults.Issues += "Certificate validation failed"
            }

            # Test attestation policies
            try {
                $policies = Get-HgsAttestationHostGroup
                $securityTests.AttestationPolicies = @{
                    Result = "Pass"
                    PolicyCount = $policies.Count
                }
            }
            catch {
                $securityTests.AttestationPolicies = @{
                    Result = "Fail"
                    Error = $_.Exception.Message
                }
                $testResults.Issues += "Attestation policy validation failed"
            }

            $testResults.Tests.Security = $securityTests
        }

        # Performance configuration test
        if ($TestType -eq "All" -or $TestType -eq "Performance") {
            Write-Host "Running performance configuration tests..." -ForegroundColor Yellow
            
            $perfTests = @{
                CPU = @{}
                Memory = @{}
                Disk = @{}
                Network = @{}
            }

            # CPU test
            $cpuUsage = (Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1).CounterSamples[0].CookedValue
            $perfTests.CPU = @{
                Result = if ($cpuUsage -lt 80) { "Pass" } else { "Warning" }
                Usage = $cpuUsage
            }

            # Memory test
            $memoryUsage = (Get-Counter "\Memory\Available MBytes").CounterSamples[0].CookedValue
            $perfTests.Memory = @{
                Result = if ($memoryUsage -gt 1000) { "Pass" } else { "Warning" }
                AvailableMB = $memoryUsage
            }

            # Disk test
            $diskQueue = (Get-Counter "\PhysicalDisk(_Total)\Current Disk Queue Length").CounterSamples[0].CookedValue
            $perfTests.Disk = @{
                Result = if ($diskQueue -lt 5) { "Pass" } else { "Warning" }
                QueueLength = $diskQueue
            }

            # Network test
            $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            $perfTests.Network = @{
                Result = if ($networkAdapters.Count -gt 0) { "Pass" } else { "Fail" }
                ActiveAdapters = $networkAdapters.Count
            }

            $testResults.Tests.Performance = $perfTests
        }

        # Determine overall result
        $failedTests = $testResults.Tests.Values | Where-Object { $_.Result -eq "Fail" }
        if ($failedTests.Count -gt 0) {
            $testResults.OverallResult = "Fail"
        }

        Write-Host "Configuration test completed. Overall result: $($testResults.OverallResult)" -ForegroundColor Green
        return $testResults
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Reset-HGSConfiguration {
    <#
    .SYNOPSIS
        Reset HGS configuration to defaults

    .DESCRIPTION
        Resets HGS configuration to default settings.

    .PARAMETER HgsServer
        HGS server name

    .PARAMETER BackupPath
        Path to backup current configuration

    .PARAMETER Force
        Force reset without confirmation

    .EXAMPLE
        Reset-HGSConfiguration -HgsServer "HGS01" -BackupPath "C:\Backup" -Force
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HgsServer = "localhost",

        [Parameter(Mandatory = $false)]
        [string]$BackupPath = "C:\HGS-Backup",

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        Write-Host "Resetting HGS configuration..." -ForegroundColor Green

        if (!$Force) {
            $confirmation = Read-Host "Are you sure you want to reset HGS configuration? This will remove all custom settings. Type 'YES' to continue"
            if ($confirmation -ne "YES") {
                Write-Host "Reset cancelled by user" -ForegroundColor Yellow
                return @{
                    Success = $false
                    Message = "Reset cancelled by user"
                }
            }
        }

        $resetResults = @{
            ServerName = $HgsServer
            Timestamp = Get-Date
            Actions = @()
            Success = $true
        }

        # Create backup
        if ($BackupPath) {
            Write-Host "Creating configuration backup..." -ForegroundColor Yellow
            try {
                if (!(Test-Path $BackupPath)) {
                    New-Item -Path $BackupPath -ItemType Directory -Force
                }
                
                $backupFile = "$BackupPath\HGS-Config-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
                Export-HgsServerConfiguration -Path $backupFile
                $resetResults.Actions += "Configuration backed up to $backupFile"
                Write-Host "Configuration backed up successfully" -ForegroundColor Green
            }
            catch {
                $resetResults.Actions += "Failed to create backup: $($_.Exception.Message)"
                Write-Warning "Failed to create backup: $($_.Exception.Message)"
            }
        }

        # Stop HGS services
        Write-Host "Stopping HGS services..." -ForegroundColor Yellow
        $hgsServices = Get-Service | Where-Object { $_.Name -like "*HGS*" }
        foreach ($service in $hgsServices) {
            try {
                Stop-Service -Name $service.Name -Force
                $resetResults.Actions += "Stopped service $($service.Name)"
            }
            catch {
                $resetResults.Actions += "Failed to stop service $($service.Name): $($_.Exception.Message)"
            }
        }

        # Reset configuration
        Write-Host "Resetting HGS configuration..." -ForegroundColor Yellow
        try {
            Initialize-HgsServer -HgsServiceName "HGS" -Force
            $resetResults.Actions += "Reset HGS configuration to defaults"
            Write-Host "HGS configuration reset successfully" -ForegroundColor Green
        }
        catch {
            $resetResults.Actions += "Failed to reset configuration: $($_.Exception.Message)"
            $resetResults.Success = $false
            Write-Warning "Failed to reset configuration: $($_.Exception.Message)"
        }

        # Restart services
        Write-Host "Restarting HGS services..." -ForegroundColor Yellow
        foreach ($service in $hgsServices) {
            try {
                Start-Service -Name $service.Name
                $resetResults.Actions += "Started service $($service.Name)"
            }
            catch {
                $resetResults.Actions += "Failed to start service $($service.Name): $($_.Exception.Message)"
                $resetResults.Success = $false
            }
        }

        Write-Host "HGS configuration reset completed" -ForegroundColor Green
        return $resetResults
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-HGSTroubleshootingGuide {
    <#
    .SYNOPSIS
        Get HGS troubleshooting guide

    .DESCRIPTION
        Provides troubleshooting guidance based on current issues.

    .PARAMETER IssueType
        Type of issue to get guidance for

    .PARAMETER Severity
        Issue severity level

    .EXAMPLE
        Get-HGSTroubleshootingGuide -IssueType "Attestation" -Severity "Critical"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Attestation", "KeyProtection", "Performance", "Network", "Certificate")]
        [string]$IssueType = "All",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$Severity = "Medium"
    )

    try {
        Write-Host "Generating troubleshooting guide..." -ForegroundColor Green

        $guide = @{
            GeneratedAt = Get-Date
            IssueType = $IssueType
            Severity = $Severity
            Steps = @()
            Resources = @()
            Commands = @()
        }

        # Attestation troubleshooting
        if ($IssueType -eq "All" -or $IssueType -eq "Attestation") {
            $guide.Steps += @{
                Category = "Attestation"
                Steps = @(
                    "Check HGS attestation service status",
                    "Verify attestation mode configuration",
                    "Review attestation host group membership",
                    "Check TPM status on hosts",
                    "Validate attestation policies"
                )
            }
            $guide.Commands += @{
                Category = "Attestation"
                Commands = @(
                    "Get-HgsServer",
                    "Get-HgsAttestationHostGroup",
                    "Test-HgsAttestationHostGroup"
                )
            }
        }

        # Key Protection troubleshooting
        if ($IssueType -eq "All" -or $IssueType -eq "KeyProtection") {
            $guide.Steps += @{
                Category = "Key Protection"
                Steps = @(
                    "Check key protection service status",
                    "Verify certificate validity",
                    "Review certificate expiration dates",
                    "Check key protection policies",
                    "Validate encryption keys"
                )
            }
            $guide.Commands += @{
                Category = "Key Protection"
                Commands = @(
                    "Get-HgsKeyProtectionCertificate",
                    "Test-HgsKeyProtectionCertificate",
                    "Set-HgsKeyProtectionCertificate"
                )
            }
        }

        # Performance troubleshooting
        if ($IssueType -eq "All" -or $IssueType -eq "Performance") {
            $guide.Steps += @{
                Category = "Performance"
                Steps = @(
                    "Check CPU usage and processor queue",
                    "Monitor memory consumption",
                    "Review disk I/O performance",
                    "Check network connectivity",
                    "Analyze event logs for performance issues"
                )
            }
            $guide.Commands += @{
                Category = "Performance"
                Commands = @(
                    "Get-Counter '\Processor(_Total)\% Processor Time'",
                    "Get-Counter '\Memory\Available MBytes'",
                    "Get-Counter '\PhysicalDisk(_Total)\Current Disk Queue Length'"
                )
            }
        }

        # Network troubleshooting
        if ($IssueType -eq "All" -or $IssueType -eq "Network") {
            $guide.Steps += @{
                Category = "Network"
                Steps = @(
                    "Test network connectivity",
                    "Check firewall rules",
                    "Verify DNS resolution",
                    "Test port accessibility",
                    "Review network adapter status"
                )
            }
            $guide.Commands += @{
                Category = "Network"
                Commands = @(
                    "Test-NetConnection",
                    "Get-NetAdapter",
                    "Test-NetConnection -ComputerName HGS01 -Port 443"
                )
            }
        }

        # Certificate troubleshooting
        if ($IssueType -eq "All" -or $IssueType -eq "Certificate") {
            $guide.Steps += @{
                Category = "Certificate"
                Steps = @(
                    "Check certificate validity",
                    "Verify certificate chain",
                    "Check certificate expiration",
                    "Review certificate store",
                    "Validate certificate permissions"
                )
            }
            $guide.Commands += @{
                Category = "Certificate"
                Commands = @(
                    "Get-ChildItem Cert:\LocalMachine\My",
                    "Get-Certificate -Thumbprint <thumbprint>",
                    "Test-Certificate -Thumbprint <thumbprint>"
                )
            }
        }

        # Add resources
        $guide.Resources = @(
            "Microsoft HGS Documentation",
            "HGS Troubleshooting Guide",
            "Windows Server Security Documentation",
            "Hyper-V Security Best Practices"
        )

        Write-Host "Troubleshooting guide generated successfully" -ForegroundColor Green
        return $guide
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
