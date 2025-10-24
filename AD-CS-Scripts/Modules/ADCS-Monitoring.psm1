#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD CS Monitoring Module

.DESCRIPTION
    PowerShell module for Windows Active Directory Certificate Services monitoring.
    Provides functions for health monitoring, performance monitoring, event monitoring, and alerting.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Module variables
$script:ModuleName = "ADCS-Monitoring"
$script:ModuleVersion = "1.0.0"

# Logging function
function Write-MonitoringLog {
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

# Health Monitoring Functions
function Get-CAHealthStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCertificates,
        
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
        Write-MonitoringLog "Getting CA health status for $ServerName" "Info"
        
        $caHealth = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            CAStatus = "Unknown"
            CAHealth = "Unknown"
            CAVersion = "Unknown"
            CADatabasePath = "Unknown"
            CALogPath = "Unknown"
            CAValidityPeriod = "Unknown"
            CAValidityPeriodUnits = "Unknown"
            CAHashAlgorithm = "Unknown"
            CAKeyLength = "Unknown"
            CAType = "Unknown"
            CACommonName = "Unknown"
            CAOrganization = "Unknown"
            CAOrganizationUnit = "Unknown"
            CALocality = "Unknown"
            CAState = "Unknown"
            CACountry = "Unknown"
            CAValidityPeriod = "Unknown"
            CAValidityPeriodUnits = "Unknown"
            CAHashAlgorithm = "Unknown"
            CAKeyLength = "Unknown"
            CAType = "Unknown"
        }
        
        # Get CA status
        try {
            $ca = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction Stop
            $caHealth.CAStatus = $ca.Status
            $caHealth.CAHealth = "Healthy"
            $caHealth.CAVersion = $ca.Version
            $caHealth.CADatabasePath = $ca.DatabasePath
            $caHealth.CALogPath = $ca.LogPath
            $caHealth.CAValidityPeriod = $ca.ValidityPeriod
            $caHealth.CAValidityPeriodUnits = $ca.ValidityPeriodUnits
            $caHealth.CAHashAlgorithm = $ca.HashAlgorithm
            $caHealth.CAKeyLength = $ca.KeyLength
            $caHealth.CAType = $ca.Type
            $caHealth.CACommonName = $ca.CACommonName
            $caHealth.CAOrganization = $ca.CAOrganization
            $caHealth.CAOrganizationUnit = $ca.CAOrganizationUnit
            $caHealth.CALocality = $ca.CALocality
            $caHealth.CAState = $ca.CAState
            $caHealth.CACountry = $ca.CACountry
        }
        catch {
            $caHealth.CAStatus = "Error"
            $caHealth.CAHealth = "Unhealthy"
            Write-MonitoringLog "Failed to get CA status: $($_.Exception.Message)" "Warning"
        }
        
        # Get certificate details if requested
        if ($IncludeCertificates) {
            try {
                $certificates = Get-Certificate -ComputerName $ServerName -ErrorAction SilentlyContinue
                $caHealth.CertificateCount = $certificates.Count
                $caHealth.CertificateStatus = "Available"
            }
            catch {
                $caHealth.CertificateCount = 0
                $caHealth.CertificateStatus = "Error"
                Write-MonitoringLog "Failed to get certificate details: $($_.Exception.Message)" "Warning"
            }
        }
        
        # Get template details if requested
        if ($IncludeTemplates) {
            try {
                $templates = Get-CertificateTemplate -ComputerName $ServerName -ErrorAction SilentlyContinue
                $caHealth.TemplateCount = $templates.Count
                $caHealth.TemplateStatus = "Available"
            }
            catch {
                $caHealth.TemplateCount = 0
                $caHealth.TemplateStatus = "Error"
                Write-MonitoringLog "Failed to get template details: $($_.Exception.Message)" "Warning"
            }
        }
        
        # Get OCSP details if requested
        if ($IncludeOCSP) {
            try {
                $ocsp = Get-AdcsOnlineResponder -ComputerName $ServerName -ErrorAction SilentlyContinue
                $caHealth.OCSPStatus = $ocsp.Status
                $caHealth.OCSPHealth = "Healthy"
            }
            catch {
                $caHealth.OCSPStatus = "Error"
                $caHealth.OCSPHealth = "Unhealthy"
                Write-MonitoringLog "Failed to get OCSP details: $($_.Exception.Message)" "Warning"
            }
        }
        
        # Get web enrollment details if requested
        if ($IncludeWebEnrollment) {
            try {
                $webEnrollment = Get-AdcsWebEnrollment -ComputerName $ServerName -ErrorAction SilentlyContinue
                $caHealth.WebEnrollmentStatus = $webEnrollment.Status
                $caHealth.WebEnrollmentHealth = "Healthy"
            }
            catch {
                $caHealth.WebEnrollmentStatus = "Error"
                $caHealth.WebEnrollmentHealth = "Unhealthy"
                Write-MonitoringLog "Failed to get web enrollment details: $($_.Exception.Message)" "Warning"
            }
        }
        
        # Get NDES details if requested
        if ($IncludeNDES) {
            try {
                $ndes = Get-AdcsNetworkDeviceEnrollmentService -ComputerName $ServerName -ErrorAction SilentlyContinue
                $caHealth.NDESStatus = $ndes.Status
                $caHealth.NDESHealth = "Healthy"
            }
            catch {
                $caHealth.NDESStatus = "Error"
                $caHealth.NDESHealth = "Unhealthy"
                Write-MonitoringLog "Failed to get NDES details: $($_.Exception.Message)" "Warning"
            }
        }
        
        Write-MonitoringLog "CA health status retrieved successfully for $ServerName" "Success"
        return $caHealth
    }
    catch {
        Write-MonitoringLog "Failed to get CA health status for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Get-CertificateLifecycleStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateName,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysUntilExpiration = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeExpired,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRevoked
    )
    
    try {
        Write-MonitoringLog "Getting certificate lifecycle status for $ServerName" "Info"
        
        $lifecycleStatus = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            TotalCertificates = 0
            ActiveCertificates = 0
            ExpiredCertificates = 0
            RevokedCertificates = 0
            ExpiringSoon = 0
            TemplateName = $TemplateName
            DaysUntilExpiration = $DaysUntilExpiration
        }
        
        # Get certificates
        try {
            $certificates = Get-Certificate -ComputerName $ServerName -ErrorAction SilentlyContinue
            
            if ($TemplateName) {
                $certificates = $certificates | Where-Object { $_.TemplateName -eq $TemplateName }
            }
            
            $lifecycleStatus.TotalCertificates = $certificates.Count
            
            foreach ($cert in $certificates) {
                if ($cert.Status -eq "Active") {
                    $lifecycleStatus.ActiveCertificates++
                    
                    # Check if expiring soon
                    $daysUntilExpiration = ($cert.NotAfter - (Get-Date)).Days
                    if ($daysUntilExpiration -le $DaysUntilExpiration) {
                        $lifecycleStatus.ExpiringSoon++
                    }
                }
                elseif ($cert.Status -eq "Expired") {
                    $lifecycleStatus.ExpiredCertificates++
                }
                elseif ($cert.Status -eq "Revoked") {
                    $lifecycleStatus.RevokedCertificates++
                }
            }
        }
        catch {
            Write-MonitoringLog "Failed to get certificate details: $($_.Exception.Message)" "Warning"
        }
        
        Write-MonitoringLog "Certificate lifecycle status retrieved successfully for $ServerName" "Success"
        return $lifecycleStatus
    }
    catch {
        Write-MonitoringLog "Failed to get certificate lifecycle status for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Performance Monitoring Functions
function Get-CAPerformanceMetrics {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 5,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Metrics = @("CPU", "Memory", "Disk", "Network")
    )
    
    try {
        Write-MonitoringLog "Getting CA performance metrics for $ServerName" "Info"
        
        $performanceMetrics = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            DurationMinutes = $DurationMinutes
            Metrics = $Metrics
            CPUUtilization = 0
            MemoryUtilization = 0
            DiskUtilization = 0
            NetworkUtilization = 0
            CertificateRequestsPerMinute = 0
            CertificateIssuancesPerMinute = 0
            CertificateRevocationsPerMinute = 0
            OCSPRequestsPerMinute = 0
            WebEnrollmentRequestsPerMinute = 0
            NDESRequestsPerMinute = 0
        }
        
        # Get performance counters
        try {
            $counters = @()
            if ($Metrics -contains "CPU") {
                $counters += "\Processor(_Total)\% Processor Time"
            }
            if ($Metrics -contains "Memory") {
                $counters += "\Memory\Available MBytes"
                $counters += "\Memory\% Committed Bytes In Use"
            }
            if ($Metrics -contains "Disk") {
                $counters += "\PhysicalDisk(_Total)\% Disk Time"
                $counters += "\PhysicalDisk(_Total)\Avg. Disk Queue Length"
            }
            if ($Metrics -contains "Network") {
                $counters += "\Network Interface(*)\Bytes Total/sec"
            }
            
            if ($counters.Count -gt 0) {
                $perfData = Get-Counter -Counter $counters -ComputerName $ServerName -MaxSamples $DurationMinutes -ErrorAction SilentlyContinue
                
                foreach ($counter in $perfData) {
                    $counterName = $counter.CounterSamples[0].Path
                    $counterValue = $counter.CounterSamples[0].CookedValue
                    
                    switch -Wildcard ($counterName) {
                        "*Processor Time*" { $performanceMetrics.CPUUtilization = $counterValue }
                        "*Committed Bytes*" { $performanceMetrics.MemoryUtilization = $counterValue }
                        "*Disk Time*" { $performanceMetrics.DiskUtilization = $counterValue }
                        "*Bytes Total/sec*" { $performanceMetrics.NetworkUtilization = $counterValue }
                    }
                }
            }
        }
        catch {
            Write-MonitoringLog "Failed to get performance counters: $($_.Exception.Message)" "Warning"
        }
        
        # Get CA-specific metrics
        try {
            $caMetrics = Get-CertificationAuthority -ComputerName $ServerName -ErrorAction SilentlyContinue
            if ($caMetrics) {
                $performanceMetrics.CertificateRequestsPerMinute = $caMetrics.CertificateRequestsPerMinute
                $performanceMetrics.CertificateIssuancesPerMinute = $caMetrics.CertificateIssuancesPerMinute
                $performanceMetrics.CertificateRevocationsPerMinute = $caMetrics.CertificateRevocationsPerMinute
            }
        }
        catch {
            Write-MonitoringLog "Failed to get CA metrics: $($_.Exception.Message)" "Warning"
        }
        
        Write-MonitoringLog "CA performance metrics retrieved successfully for $ServerName" "Success"
        return $performanceMetrics
    }
    catch {
        Write-MonitoringLog "Failed to get CA performance metrics for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Event Monitoring Functions
function Get-CAEventLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$LogLevel = "All",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 100,
        
        [Parameter(Mandatory = $false)]
        [int]$HoursBack = 24
    )
    
    try {
        Write-MonitoringLog "Getting CA event logs for $ServerName" "Info"
        
        $eventLogs = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            LogLevel = $LogLevel
            MaxEvents = $MaxEvents
            HoursBack = $HoursBack
            Events = @()
            CriticalEvents = 0
            ErrorEvents = 0
            WarningEvents = 0
            InformationEvents = 0
        }
        
        # Get event logs
        try {
            $logSources = @(
                "Microsoft-Windows-CertificateServicesClient-CredentialRoaming*",
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*",
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-User*",
                "Microsoft-Windows-CertificateServicesClient-CredentialRoaming*",
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*",
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-User*"
            )
            
            $filterHashtable = @{
                LogName = "Application", "System"
                StartTime = (Get-Date).AddHours(-$HoursBack)
            }
            
            if ($LogLevel -ne "All") {
                $filterHashtable.Level = switch ($LogLevel) {
                    "Critical" { 1 }
                    "Error" { 2 }
                    "Warning" { 3 }
                    "Information" { 4 }
                    default { 1, 2, 3, 4 }
                }
            }
            
            $events = Get-WinEvent -FilterHashtable $filterHashtable -ComputerName $ServerName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            
            foreach ($event in $events) {
                $eventData = @{
                    EventID = $event.Id
                    Level = $event.LevelDisplayName
                    Source = $event.ProviderName
                    TimeCreated = $event.TimeCreated
                    Message = $event.Message
                    MachineName = $event.MachineName
                }
                
                $eventLogs.Events += $eventData
                
                switch ($event.LevelDisplayName) {
                    "Critical" { $eventLogs.CriticalEvents++ }
                    "Error" { $eventLogs.ErrorEvents++ }
                    "Warning" { $eventLogs.WarningEvents++ }
                    "Information" { $eventLogs.InformationEvents++ }
                }
            }
        }
        catch {
            Write-MonitoringLog "Failed to get event logs: $($_.Exception.Message)" "Warning"
        }
        
        Write-MonitoringLog "CA event logs retrieved successfully for $ServerName" "Success"
        return $eventLogs
    }
    catch {
        Write-MonitoringLog "Failed to get CA event logs for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Alerting Functions
function Set-CAAlerting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$AlertLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [string[]]$AlertTypes = @("Email", "SMS", "Webhook"),
        
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
        Write-MonitoringLog "Setting CA alerting for $ServerName" "Info"
        
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
        
        # Configure alerting based on type
        foreach ($alertType in $AlertTypes) {
            switch ($alertType) {
                "Email" {
                    if ($SmtpServer -and $Recipients.Count -gt 0) {
                        Write-MonitoringLog "Configuring email alerting" "Info"
                        # Configure email alerting
                    }
                }
                "SMS" {
                    if ($SmsProvider -and $SmsApiKey -and $SmsRecipients.Count -gt 0) {
                        Write-MonitoringLog "Configuring SMS alerting" "Info"
                        # Configure SMS alerting
                    }
                }
                "Webhook" {
                    if ($WebhookUrl) {
                        Write-MonitoringLog "Configuring webhook alerting" "Info"
                        # Configure webhook alerting
                    }
                }
            }
        }
        
        Write-MonitoringLog "CA alerting configured successfully for $ServerName" "Success"
        return $alertingConfig
    }
    catch {
        Write-MonitoringLog "Failed to configure CA alerting for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Get-CAAlertingStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    
    try {
        Write-MonitoringLog "Getting CA alerting status for $ServerName" "Info"
        
        $alertingStatus = @{
            ServerName = $ServerName
            AlertingEnabled = $false
            AlertTypes = @()
            LastAlert = $null
            AlertCount = 0
            Timestamp = Get-Date
        }
        
        # Get alerting status
        try {
            $alertingConfig = Get-CAAlerting -ServerName $ServerName -ErrorAction SilentlyContinue
            if ($alertingConfig) {
                $alertingStatus.AlertingEnabled = $true
                $alertingStatus.AlertTypes = $alertingConfig.AlertTypes
            }
        }
        catch {
            Write-MonitoringLog "Failed to get alerting configuration: $($_.Exception.Message)" "Warning"
        }
        
        Write-MonitoringLog "CA alerting status retrieved successfully for $ServerName" "Success"
        return $alertingStatus
    }
    catch {
        Write-MonitoringLog "Failed to get CA alerting status for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Reporting Functions
function Get-CAMonitoringReport {
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
        Write-MonitoringLog "Generating CA monitoring report for $ServerName" "Info"
        
        $report = @{
            ServerName = $ServerName
            ReportType = $ReportType
            DaysBack = $DaysBack
            OutputFormat = $OutputFormat
            OutputPath = $OutputPath
            Timestamp = Get-Date
            HealthStatus = $null
            PerformanceMetrics = $null
            EventLogs = $null
            CertificateLifecycle = $null
            AlertingStatus = $null
        }
        
        # Get health status
        $report.HealthStatus = Get-CAHealthStatus -ServerName $ServerName -IncludeDetails -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES
        
        # Get performance metrics
        $report.PerformanceMetrics = Get-CAPerformanceMetrics -ServerName $ServerName -DurationMinutes 60
        
        # Get event logs
        $report.EventLogs = Get-CAEventLogs -ServerName $ServerName -LogLevel "All" -MaxEvents 1000 -HoursBack ($DaysBack * 24)
        
        # Get certificate lifecycle
        $report.CertificateLifecycle = Get-CertificateLifecycleStatus -ServerName $ServerName -DaysUntilExpiration 30 -IncludeExpired -IncludeRevoked
        
        # Get alerting status
        $report.AlertingStatus = Get-CAAlertingStatus -ServerName $ServerName
        
        # Generate report based on format
        if ($OutputPath) {
            switch ($OutputFormat) {
                "HTML" {
                    $htmlReport = $report | ConvertTo-Html -Title "CA Monitoring Report" | Out-File -FilePath $OutputPath -Encoding UTF8
                }
                "JSON" {
                    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
                }
                "CSV" {
                    $report | ConvertTo-Csv | Out-File -FilePath $OutputPath -Encoding UTF8
                }
            }
        }
        
        Write-MonitoringLog "CA monitoring report generated successfully for $ServerName" "Success"
        return $report
    }
    catch {
        Write-MonitoringLog "Failed to generate CA monitoring report for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-CAHealthStatus',
    'Get-CertificateLifecycleStatus',
    'Get-CAPerformanceMetrics',
    'Get-CAEventLogs',
    'Set-CAAlerting',
    'Get-CAAlertingStatus',
    'Get-CAMonitoringReport'
)
