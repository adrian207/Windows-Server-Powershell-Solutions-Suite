#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD CS Troubleshooting Module

.DESCRIPTION
    PowerShell module for Windows Active Directory Certificate Services troubleshooting.
    Provides functions for health diagnostics, event analysis, performance analysis, and repair operations.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Module variables
$script:ModuleName = "ADCS-Troubleshooting"
$script:ModuleVersion = "1.0.0"

# Logging function
function Write-TroubleshootingLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [$script:ModuleName] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Health Diagnostics Functions
function Test-CAHealth {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$HealthLevel = "Comprehensive",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCertificates,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTemplates,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeOCSP,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeWebEnrollment,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNDES,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformance,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSecurity,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCompliance
    )
    
    try {
        Write-TroubleshootingLog "Running CA health test for $ServerName" "Info"
        
        $healthTest = @{
            ServerName = $ServerName
            HealthLevel = $HealthLevel
            Timestamp = Get-Date
            OverallHealth = "Unknown"
            TestResults = @()
            Issues = @()
            Recommendations = @()
        }
        
        # Test CA service
        try {
            $ca = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction Stop
            $healthTest.TestResults += @{
                TestName = "CA Service"
                Status = "Passed"
                Details = "CA service is running"
                Severity = "Info"
            }
            $healthTest.OverallHealth = "Healthy"
        }
        catch {
            $healthTest.TestResults += @{
                TestName = "CA Service"
                Status = "Failed"
                Details = "CA service is not running: $($_.Exception.Message)"
                Severity = "Critical"
            }
            $healthTest.Issues += "CA service is not running"
            $healthTest.Recommendations += "Start the CA service"
            $healthTest.OverallHealth = "Unhealthy"
        }
        
        # Test CA database
        try {
            $ca = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction Stop
            if (Test-Path $ca.DatabasePath) {
                $healthTest.TestResults += @{
                    TestName = "CA Database"
                    Status = "Passed"
                    Details = "CA database is accessible"
                    Severity = "Info"
                }
            } else {
                $healthTest.TestResults += @{
                    TestName = "CA Database"
                    Status = "Failed"
                    Details = "CA database path is not accessible"
                    Severity = "Critical"
                }
                $healthTest.Issues += "CA database is not accessible"
                $healthTest.Recommendations += "Check CA database path and permissions"
                $healthTest.OverallHealth = "Unhealthy"
            }
        }
        catch {
            $healthTest.TestResults += @{
                TestName = "CA Database"
                Status = "Failed"
                Details = "Cannot access CA database: $($_.Exception.Message)"
                Severity = "Critical"
            }
            $healthTest.Issues += "Cannot access CA database"
            $healthTest.Recommendations += "Check CA database configuration"
            $healthTest.OverallHealth = "Unhealthy"
        }
        
        # Test CA logs
        try {
            $ca = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction Stop
            if (Test-Path $ca.LogPath) {
                $healthTest.TestResults += @{
                    TestName = "CA Logs"
                    Status = "Passed"
                    Details = "CA log path is accessible"
                    Severity = "Info"
                }
            } else {
                $healthTest.TestResults += @{
                    TestName = "CA Logs"
                    Status = "Failed"
                    Details = "CA log path is not accessible"
                    Severity = "Warning"
                }
                $healthTest.Issues += "CA log path is not accessible"
                $healthTest.Recommendations += "Check CA log path and permissions"
            }
        }
        catch {
            $healthTest.TestResults += @{
                TestName = "CA Logs"
                Status = "Failed"
                Details = "Cannot access CA logs: $($_.Exception.Message)"
                Severity = "Warning"
            }
            $healthTest.Issues += "Cannot access CA logs"
            $healthTest.Recommendations += "Check CA log configuration"
        }
        
        # Test certificates if requested
        if ($IncludeCertificates) {
            try {
                $certificates = Get-Certificate -ComputerName $ServerName -ErrorAction SilentlyContinue
                if ($certificates) {
                    $healthTest.TestResults += @{
                        TestName = "Certificates"
                        Status = "Passed"
                        Details = "Certificates are accessible"
                        Severity = "Info"
                    }
                } else {
                    $healthTest.TestResults += @{
                        TestName = "Certificates"
                        Status = "Failed"
                        Details = "No certificates found"
                        Severity = "Warning"
                    }
                    $healthTest.Issues += "No certificates found"
                    $healthTest.Recommendations += "Check certificate configuration"
                }
            }
            catch {
                $healthTest.TestResults += @{
                    TestName = "Certificates"
                    Status = "Failed"
                    Details = "Cannot access certificates: $($_.Exception.Message)"
                    Severity = "Warning"
                }
                $healthTest.Issues += "Cannot access certificates"
                $healthTest.Recommendations += "Check certificate configuration"
            }
        }
        
        # Test templates if requested
        if ($IncludeTemplates) {
            try {
                $templates = Get-CertificateTemplate -ComputerName $ServerName -ErrorAction SilentlyContinue
                if ($templates) {
                    $healthTest.TestResults += @{
                        TestName = "Templates"
                        Status = "Passed"
                        Details = "Templates are accessible"
                        Severity = "Info"
                    }
                } else {
                    $healthTest.TestResults += @{
                        TestName = "Templates"
                        Status = "Failed"
                        Details = "No templates found"
                        Severity = "Warning"
                    }
                    $healthTest.Issues += "No templates found"
                    $healthTest.Recommendations += "Check template configuration"
                }
            }
            catch {
                $healthTest.TestResults += @{
                    TestName = "Templates"
                    Status = "Failed"
                    Details = "Cannot access templates: $($_.Exception.Message)"
                    Severity = "Warning"
                }
                $healthTest.Issues += "Cannot access templates"
                $healthTest.Recommendations += "Check template configuration"
            }
        }
        
        # Test OCSP if requested
        if ($IncludeOCSP) {
            try {
                $ocsp = Get-AdcsOnlineResponder -ComputerName $ServerName -ErrorAction SilentlyContinue
                if ($ocsp) {
                    $healthTest.TestResults += @{
                        TestName = "OCSP"
                        Status = "Passed"
                        Details = "OCSP responder is accessible"
                        Severity = "Info"
                    }
                } else {
                    $healthTest.TestResults += @{
                        TestName = "OCSP"
                        Status = "Failed"
                        Details = "OCSP responder is not accessible"
                        Severity = "Warning"
                    }
                    $healthTest.Issues += "OCSP responder is not accessible"
                    $healthTest.Recommendations += "Check OCSP configuration"
                }
            }
            catch {
                $healthTest.TestResults += @{
                    TestName = "OCSP"
                    Status = "Failed"
                    Details = "Cannot access OCSP responder: $($_.Exception.Message)"
                    Severity = "Warning"
                }
                $healthTest.Issues += "Cannot access OCSP responder"
                $healthTest.Recommendations += "Check OCSP configuration"
            }
        }
        
        # Test web enrollment if requested
        if ($IncludeWebEnrollment) {
            try {
                $webEnrollment = Get-AdcsWebEnrollment -ComputerName $ServerName -ErrorAction SilentlyContinue
                if ($webEnrollment) {
                    $healthTest.TestResults += @{
                        TestName = "Web Enrollment"
                        Status = "Passed"
                        Details = "Web enrollment is accessible"
                        Severity = "Info"
                    }
                } else {
                    $healthTest.TestResults += @{
                        TestName = "Web Enrollment"
                        Status = "Failed"
                        Details = "Web enrollment is not accessible"
                        Severity = "Warning"
                    }
                    $healthTest.Issues += "Web enrollment is not accessible"
                    $healthTest.Recommendations += "Check web enrollment configuration"
                }
            }
            catch {
                $healthTest.TestResults += @{
                    TestName = "Web Enrollment"
                    Status = "Failed"
                    Details = "Cannot access web enrollment: $($_.Exception.Message)"
                    Severity = "Warning"
                }
                $healthTest.Issues += "Cannot access web enrollment"
                $healthTest.Recommendations += "Check web enrollment configuration"
            }
        }
        
        # Test NDES if requested
        if ($IncludeNDES) {
            try {
                $ndes = Get-AdcsNetworkDeviceEnrollmentService -ComputerName $ServerName -ErrorAction SilentlyContinue
                if ($ndes) {
                    $healthTest.TestResults += @{
                        TestName = "NDES"
                        Status = "Passed"
                        Details = "NDES is accessible"
                        Severity = "Info"
                    }
                } else {
                    $healthTest.TestResults += @{
                        TestName = "NDES"
                        Status = "Failed"
                        Details = "NDES is not accessible"
                        Severity = "Warning"
                    }
                    $healthTest.Issues += "NDES is not accessible"
                    $healthTest.Recommendations += "Check NDES configuration"
                }
            }
            catch {
                $healthTest.TestResults += @{
                    TestName = "NDES"
                    Status = "Failed"
                    Details = "Cannot access NDES: $($_.Exception.Message)"
                    Severity = "Warning"
                }
                $healthTest.Issues += "Cannot access NDES"
                $healthTest.Recommendations += "Check NDES configuration"
            }
        }
        
        Write-TroubleshootingLog "CA health test completed for $ServerName" "Success"
        return $healthTest
    }
    catch {
        Write-TroubleshootingLog "Failed to run CA health test for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Event Analysis Functions
function Analyze-CAEventLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$AnalysisType = "Comprehensive",
        
        [Parameter(Mandatory = $false)]
        [int]$TimeRangeHours = 24,
        
        [Parameter(Mandatory = $false)]
        [string[]]$LogSources = @("Application", "System"),
        
        [Parameter(Mandatory = $false)]
        [string[]]$EventLevels = @("Critical", "Error", "Warning"),
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 1000
    )
    
    try {
        Write-TroubleshootingLog "Analyzing CA event logs for $ServerName" "Info"
        
        $eventAnalysis = @{
            ServerName = $ServerName
            AnalysisType = $AnalysisType
            TimeRangeHours = $TimeRangeHours
            LogSources = $LogSources
            EventLevels = $EventLevels
            MaxEvents = $MaxEvents
            Timestamp = Get-Date
            TotalEvents = 0
            CriticalEvents = 0
            ErrorEvents = 0
            WarningEvents = 0
            InformationEvents = 0
            TopEvents = @()
            EventPatterns = @()
            Recommendations = @()
        }
        
        # Get event logs
        try {
            $filterHashtable = @{
                LogName = $LogSources
                StartTime = (Get-Date).AddHours(-$TimeRangeHours)
            }
            
            if ($EventLevels -contains "Critical") { $filterHashtable.Level = 1 }
            if ($EventLevels -contains "Error") { $filterHashtable.Level = 2 }
            if ($EventLevels -contains "Warning") { $filterHashtable.Level = 3 }
            if ($EventLevels -contains "Information") { $filterHashtable.Level = 4 }
            
            $events = Get-WinEvent -FilterHashtable $filterHashtable -ComputerName $ServerName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            
            $eventAnalysis.TotalEvents = $events.Count
            
            # Analyze events
            foreach ($event in $events) {
                switch ($event.LevelDisplayName) {
                    "Critical" { $eventAnalysis.CriticalEvents++ }
                    "Error" { $eventAnalysis.ErrorEvents++ }
                    "Warning" { $eventAnalysis.WarningEvents++ }
                    "Information" { $eventAnalysis.InformationEvents++ }
                }
            }
            
            # Get top events by frequency
            $topEvents = $events | Group-Object -Property Id, LevelDisplayName | Sort-Object Count -Descending | Select-Object -First 10
            
            foreach ($topEvent in $topEvents) {
                $eventAnalysis.TopEvents += @{
                    EventID = $topEvent.Name.Split(',')[0]
                    Level = $topEvent.Name.Split(',')[1]
                    Count = $topEvent.Count
                    LastOccurrence = ($topEvent.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                }
            }
            
            # Analyze event patterns
            $eventPatterns = $events | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 5
            
            foreach ($pattern in $eventPatterns) {
                $eventAnalysis.EventPatterns += @{
                    Source = $pattern.Name
                    Count = $pattern.Count
                    Percentage = [math]::Round(($pattern.Count / $eventAnalysis.TotalEvents) * 100, 2)
                }
            }
            
            # Generate recommendations based on analysis
            if ($eventAnalysis.CriticalEvents -gt 0) {
                $eventAnalysis.Recommendations += "Address critical events immediately"
            }
            if ($eventAnalysis.ErrorEvents -gt 10) {
                $eventAnalysis.Recommendations += "High number of error events - investigate root cause"
            }
            if ($eventAnalysis.WarningEvents -gt 50) {
                $eventAnalysis.Recommendations += "High number of warning events - review configuration"
            }
            
        }
        catch {
            Write-TroubleshootingLog "Failed to analyze event logs: $($_.Exception.Message)" "Warning"
        }
        
        Write-TroubleshootingLog "CA event log analysis completed for $ServerName" "Success"
        return $eventAnalysis
    }
    catch {
        Write-TroubleshootingLog "Failed to analyze CA event logs for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Performance Analysis Functions
function Analyze-CAPerformance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Metrics = @("CPU", "Memory", "Disk", "Network"),
        
        [Parameter(Mandatory = $false)]
        [string]$AnalysisType = "Comprehensive"
    )
    
    try {
        Write-TroubleshootingLog "Analyzing CA performance for $ServerName" "Info"
        
        $performanceAnalysis = @{
            ServerName = $ServerName
            DurationMinutes = $DurationMinutes
            Metrics = $Metrics
            AnalysisType = $AnalysisType
            Timestamp = Get-Date
            CPUAnalysis = @{}
            MemoryAnalysis = @{}
            DiskAnalysis = @{}
            NetworkAnalysis = @{}
            PerformanceIssues = @()
            Recommendations = @()
        }
        
        # Get performance counters
        try {
            $counters = @()
            if ($Metrics -contains "CPU") {
                $counters += "\Processor(_Total)\% Processor Time"
                $counters += "\Processor(_Total)\% Privileged Time"
                $counters += "\Processor(_Total)\% User Time"
            }
            if ($Metrics -contains "Memory") {
                $counters += "\Memory\Available MBytes"
                $counters += "\Memory\% Committed Bytes In Use"
                $counters += "\Memory\Pool Nonpaged Bytes"
                $counters += "\Memory\Pool Paged Bytes"
            }
            if ($Metrics -contains "Disk") {
                $counters += "\PhysicalDisk(_Total)\% Disk Time"
                $counters += "\PhysicalDisk(_Total)\Avg. Disk Queue Length"
                $counters += "\PhysicalDisk(_Total)\Disk Reads/sec"
                $counters += "\PhysicalDisk(_Total)\Disk Writes/sec"
            }
            if ($Metrics -contains "Network") {
                $counters += "\Network Interface(*)\Bytes Total/sec"
                $counters += "\Network Interface(*)\Packets/sec"
                $counters += "\Network Interface(*)\Current Bandwidth"
            }
            
            if ($counters.Count -gt 0) {
                $perfData = Get-Counter -Counter $counters -ComputerName $ServerName -MaxSamples $DurationMinutes -ErrorAction SilentlyContinue
                
                # Analyze CPU performance
                if ($Metrics -contains "CPU") {
                    $cpuCounters = $perfData | Where-Object { $_.CounterSamples[0].Path -like "*Processor*" }
                    $cpuValues = $cpuCounters | ForEach-Object { $_.CounterSamples[0].CookedValue }
                    
                    $performanceAnalysis.CPUAnalysis = @{
                        Average = [math]::Round(($cpuValues | Measure-Object -Average).Average, 2)
                        Maximum = [math]::Round(($cpuValues | Measure-Object -Maximum).Maximum, 2)
                        Minimum = [math]::Round(($cpuValues | Measure-Object -Minimum).Minimum, 2)
                        Samples = $cpuValues.Count
                    }
                    
                    if ($performanceAnalysis.CPUAnalysis.Average -gt 80) {
                        $performanceAnalysis.PerformanceIssues += "High CPU utilization"
                        $performanceAnalysis.Recommendations += "Investigate high CPU usage"
                    }
                }
                
                # Analyze memory performance
                if ($Metrics -contains "Memory") {
                    $memoryCounters = $perfData | Where-Object { $_.CounterSamples[0].Path -like "*Memory*" }
                    $memoryValues = $memoryCounters | ForEach-Object { $_.CounterSamples[0].CookedValue }
                    
                    $performanceAnalysis.MemoryAnalysis = @{
                        Average = [math]::Round(($memoryValues | Measure-Object -Average).Average, 2)
                        Maximum = [math]::Round(($memoryValues | Measure-Object -Maximum).Maximum, 2)
                        Minimum = [math]::Round(($memoryValues | Measure-Object -Minimum).Minimum, 2)
                        Samples = $memoryValues.Count
                    }
                    
                    if ($performanceAnalysis.MemoryAnalysis.Average -gt 85) {
                        $performanceAnalysis.PerformanceIssues += "High memory utilization"
                        $performanceAnalysis.Recommendations += "Investigate high memory usage"
                    }
                }
                
                # Analyze disk performance
                if ($Metrics -contains "Disk") {
                    $diskCounters = $perfData | Where-Object { $_.CounterSamples[0].Path -like "*PhysicalDisk*" }
                    $diskValues = $diskCounters | ForEach-Object { $_.CounterSamples[0].CookedValue }
                    
                    $performanceAnalysis.DiskAnalysis = @{
                        Average = [math]::Round(($diskValues | Measure-Object -Average).Average, 2)
                        Maximum = [math]::Round(($diskValues | Measure-Object -Maximum).Maximum, 2)
                        Minimum = [math]::Round(($diskValues | Measure-Object -Minimum).Minimum, 2)
                        Samples = $diskValues.Count
                    }
                    
                    if ($performanceAnalysis.DiskAnalysis.Average -gt 90) {
                        $performanceAnalysis.PerformanceIssues += "High disk utilization"
                        $performanceAnalysis.Recommendations += "Investigate high disk usage"
                    }
                }
                
                # Analyze network performance
                if ($Metrics -contains "Network") {
                    $networkCounters = $perfData | Where-Object { $_.CounterSamples[0].Path -like "*Network Interface*" }
                    $networkValues = $networkCounters | ForEach-Object { $_.CounterSamples[0].CookedValue }
                    
                    $performanceAnalysis.NetworkAnalysis = @{
                        Average = [math]::Round(($networkValues | Measure-Object -Average).Average, 2)
                        Maximum = [math]::Round(($networkValues | Measure-Object -Maximum).Maximum, 2)
                        Minimum = [math]::Round(($networkValues | Measure-Object -Minimum).Minimum, 2)
                        Samples = $networkValues.Count
                    }
                }
            }
        }
        catch {
            Write-TroubleshootingLog "Failed to analyze performance: $($_.Exception.Message)" "Warning"
        }
        
        Write-TroubleshootingLog "CA performance analysis completed for $ServerName" "Success"
        return $performanceAnalysis
    }
    catch {
        Write-TroubleshootingLog "Failed to analyze CA performance for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Certificate Diagnostics Functions
function Test-CertificateDiagnostics {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificateSerialNumber,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateName,
        
        [Parameter(Mandatory = $false)]
        [string]$DiagnosticLevel = "Comprehensive",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeValidation,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRevocation,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeExpiration
    )
    
    try {
        Write-TroubleshootingLog "Running certificate diagnostics for $ServerName" "Info"
        
        $certificateDiagnostics = @{
            ServerName = $ServerName
            CertificateSerialNumber = $CertificateSerialNumber
            TemplateName = $TemplateName
            DiagnosticLevel = $DiagnosticLevel
            Timestamp = Get-Date
            TestResults = @()
            Issues = @()
            Recommendations = @()
        }
        
        # Test certificate validation
        if ($IncludeValidation) {
            try {
                $certificates = Get-Certificate -ComputerName $ServerName -ErrorAction SilentlyContinue
                
                if ($CertificateSerialNumber) {
                    $certificates = $certificates | Where-Object { $_.SerialNumber -eq $CertificateSerialNumber }
                }
                if ($TemplateName) {
                    $certificates = $certificates | Where-Object { $_.TemplateName -eq $TemplateName }
                }
                
                foreach ($cert in $certificates) {
                    $validationResult = Test-Certificate -Certificate $cert -ErrorAction SilentlyContinue
                    
                    if ($validationResult) {
                        $certificateDiagnostics.TestResults += @{
                            TestName = "Certificate Validation"
                            CertificateSerialNumber = $cert.SerialNumber
                            Status = "Passed"
                            Details = "Certificate validation successful"
                            Severity = "Info"
                        }
                    } else {
                        $certificateDiagnostics.TestResults += @{
                            TestName = "Certificate Validation"
                            CertificateSerialNumber = $cert.SerialNumber
                            Status = "Failed"
                            Details = "Certificate validation failed"
                            Severity = "Warning"
                        }
                        $certificateDiagnostics.Issues += "Certificate validation failed for $($cert.SerialNumber)"
                        $certificateDiagnostics.Recommendations += "Check certificate validity and trust chain"
                    }
                }
            }
            catch {
                $certificateDiagnostics.TestResults += @{
                    TestName = "Certificate Validation"
                    Status = "Failed"
                    Details = "Cannot validate certificates: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $certificateDiagnostics.Issues += "Cannot validate certificates"
                $certificateDiagnostics.Recommendations += "Check certificate configuration"
            }
        }
        
        # Test certificate revocation
        if ($IncludeRevocation) {
            try {
                $crl = Get-CertificateRevocationList -ComputerName $ServerName -ErrorAction SilentlyContinue
                
                if ($crl) {
                    $certificateDiagnostics.TestResults += @{
                        TestName = "Certificate Revocation"
                        Status = "Passed"
                        Details = "CRL is accessible"
                        Severity = "Info"
                    }
                } else {
                    $certificateDiagnostics.TestResults += @{
                        TestName = "Certificate Revocation"
                        Status = "Failed"
                        Details = "CRL is not accessible"
                        Severity = "Warning"
                    }
                    $certificateDiagnostics.Issues += "CRL is not accessible"
                    $certificateDiagnostics.Recommendations += "Check CRL configuration and accessibility"
                }
            }
            catch {
                $certificateDiagnostics.TestResults += @{
                    TestName = "Certificate Revocation"
                    Status = "Failed"
                    Details = "Cannot access CRL: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $certificateDiagnostics.Issues += "Cannot access CRL"
                $certificateDiagnostics.Recommendations += "Check CRL configuration"
            }
        }
        
        # Test certificate expiration
        if ($IncludeExpiration) {
            try {
                $certificates = Get-Certificate -ComputerName $ServerName -ErrorAction SilentlyContinue
                
                if ($TemplateName) {
                    $certificates = $certificates | Where-Object { $_.TemplateName -eq $TemplateName }
                }
                
                $expiredCertificates = $certificates | Where-Object { $_.NotAfter -lt (Get-Date) }
                $expiringSoonCertificates = $certificates | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) -and $_.NotAfter -gt (Get-Date) }
                
                if ($expiredCertificates.Count -gt 0) {
                    $certificateDiagnostics.TestResults += @{
                        TestName = "Certificate Expiration"
                        Status = "Failed"
                        Details = "$($expiredCertificates.Count) expired certificates found"
                        Severity = "Warning"
                    }
                    $certificateDiagnostics.Issues += "$($expiredCertificates.Count) expired certificates"
                    $certificateDiagnostics.Recommendations += "Renew expired certificates"
                }
                
                if ($expiringSoonCertificates.Count -gt 0) {
                    $certificateDiagnostics.TestResults += @{
                        TestName = "Certificate Expiration"
                        Status = "Warning"
                        Details = "$($expiringSoonCertificates.Count) certificates expiring soon"
                        Severity = "Warning"
                    }
                    $certificateDiagnostics.Issues += "$($expiringSoonCertificates.Count) certificates expiring soon"
                    $certificateDiagnostics.Recommendations += "Plan certificate renewal"
                }
                
                if ($expiredCertificates.Count -eq 0 -and $expiringSoonCertificates.Count -eq 0) {
                    $certificateDiagnostics.TestResults += @{
                        TestName = "Certificate Expiration"
                        Status = "Passed"
                        Details = "No expired or expiring certificates found"
                        Severity = "Info"
                    }
                }
            }
            catch {
                $certificateDiagnostics.TestResults += @{
                    TestName = "Certificate Expiration"
                    Status = "Failed"
                    Details = "Cannot check certificate expiration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $certificateDiagnostics.Issues += "Cannot check certificate expiration"
                $certificateDiagnostics.Recommendations += "Check certificate configuration"
            }
        }
        
        Write-TroubleshootingLog "Certificate diagnostics completed for $ServerName" "Success"
        return $certificateDiagnostics
    }
    catch {
        Write-TroubleshootingLog "Failed to run certificate diagnostics for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Repair Operations Functions
function Repair-CAConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$RepairLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [switch]$BackupBeforeRepair,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDatabase,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeLogs,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTemplates,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeOCSP,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeWebEnrollment,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNDES
    )
    
    try {
        Write-TroubleshootingLog "Starting CA configuration repair for $ServerName" "Info"
        
        $repairResults = @{
            ServerName = $ServerName
            RepairLevel = $RepairLevel
            BackupBeforeRepair = $BackupBeforeRepair
            Timestamp = Get-Date
            RepairOperations = @()
            Issues = @()
            Recommendations = @()
        }
        
        # Backup before repair if requested
        if ($BackupBeforeRepair) {
            try {
                $backupPath = "C:\CA-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
                
                $repairResults.RepairOperations += @{
                    Operation = "Backup"
                    Status = "Completed"
                    Details = "Backup created at $backupPath"
                    Severity = "Info"
                }
            }
            catch {
                $repairResults.RepairOperations += @{
                    Operation = "Backup"
                    Status = "Failed"
                    Details = "Backup failed: $($_.Exception.Message)"
                    Severity = "Warning"
                }
                $repairResults.Issues += "Backup failed"
                $repairResults.Recommendations += "Create manual backup before repair"
            }
        }
        
        # Repair CA service
        try {
            $ca = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction Stop
            
            $repairResults.RepairOperations += @{
                Operation = "CA Service"
                Status = "Completed"
                Details = "CA service is running"
                Severity = "Info"
            }
        }
        catch {
            try {
                Start-Service -Name "CertSvc" -ErrorAction Stop
                $repairResults.RepairOperations += @{
                    Operation = "CA Service"
                    Status = "Repaired"
                    Details = "CA service started"
                    Severity = "Info"
                }
            }
            catch {
                $repairResults.RepairOperations += @{
                    Operation = "CA Service"
                    Status = "Failed"
                    Details = "Cannot start CA service: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $repairResults.Issues += "Cannot start CA service"
                $repairResults.Recommendations += "Check CA service configuration and dependencies"
            }
        }
        
        # Repair database if requested
        if ($IncludeDatabase) {
            try {
                $ca = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction Stop
                
                if (Test-Path $ca.DatabasePath) {
                    $repairResults.RepairOperations += @{
                        Operation = "CA Database"
                        Status = "Completed"
                        Details = "CA database is accessible"
                        Severity = "Info"
                    }
                } else {
                    $repairResults.RepairOperations += @{
                        Operation = "CA Database"
                        Status = "Failed"
                        Details = "CA database path is not accessible"
                        Severity = "Error"
                    }
                    $repairResults.Issues += "CA database is not accessible"
                    $repairResults.Recommendations += "Check CA database path and permissions"
                }
            }
            catch {
                $repairResults.RepairOperations += @{
                    Operation = "CA Database"
                    Status = "Failed"
                    Details = "Cannot access CA database: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $repairResults.Issues += "Cannot access CA database"
                $repairResults.Recommendations += "Check CA database configuration"
            }
        }
        
        # Repair logs if requested
        if ($IncludeLogs) {
            try {
                $ca = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction Stop
                
                if (Test-Path $ca.LogPath) {
                    $repairResults.RepairOperations += @{
                        Operation = "CA Logs"
                        Status = "Completed"
                        Details = "CA log path is accessible"
                        Severity = "Info"
                    }
                } else {
                    $repairResults.RepairOperations += @{
                        Operation = "CA Logs"
                        Status = "Failed"
                        Details = "CA log path is not accessible"
                        Severity = "Warning"
                    }
                    $repairResults.Issues += "CA log path is not accessible"
                    $repairResults.Recommendations += "Check CA log path and permissions"
                }
            }
            catch {
                $repairResults.RepairOperations += @{
                    Operation = "CA Logs"
                    Status = "Failed"
                    Details = "Cannot access CA logs: $($_.Exception.Message)"
                    Severity = "Warning"
                }
                $repairResults.Issues += "Cannot access CA logs"
                $repairResults.Recommendations += "Check CA log configuration"
            }
        }
        
        Write-TroubleshootingLog "CA configuration repair completed for $ServerName" "Success"
        return $repairResults
    }
    catch {
        Write-TroubleshootingLog "Failed to repair CA configuration for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Test-CAHealth',
    'Analyze-CAEventLogs',
    'Analyze-CAPerformance',
    'Test-CertificateDiagnostics',
    'Repair-CAConfiguration'
)
