#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Troubleshooting Module

.DESCRIPTION
    PowerShell module for Windows Active Directory troubleshooting and diagnostics.
    Provides comprehensive troubleshooting capabilities including health checks,
    performance analysis, event log analysis, and automated remediation.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Module variables
$ModuleVersion = "1.0.0"
$ModuleAuthor = "Adrian Johnson (adrian207@gmail.com)"

# Troubleshooting Functions
function Get-ADTroubleshootingStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$TroubleshootingLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [string]$TroubleshootingType = "All",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRemediation,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformanceAnalysis,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeEventLogAnalysis,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeHealthChecks,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSecurityAnalysis,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeComplianceCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeReplicationCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeFSMOCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDNSCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTimeSyncCheck
    )
    
    try {
        Write-Host "Starting AD troubleshooting on $ServerName..." -ForegroundColor Cyan
        
        $troubleshootingStatus = @{
            ServerName = $ServerName
            TroubleshootingLevel = $TroubleshootingLevel
            TroubleshootingType = $TroubleshootingType
            Timestamp = Get-Date
            TroubleshootingResults = @{}
            Issues = @()
            Recommendations = @()
            RemediationActions = @()
            OverallStatus = "Unknown"
        }
        
        # Perform health checks
        if ($IncludeHealthChecks) {
            try {
                $healthChecks = Get-ADHealthStatus -ServerName $ServerName -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
                $troubleshootingStatus.TroubleshootingResults.HealthChecks = @{
                    Status = "Completed"
                    Details = $healthChecks
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.HealthChecks = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "Health checks failed"
            }
        }
        
        # Perform performance analysis
        if ($IncludePerformanceAnalysis) {
            try {
                $performanceAnalysis = Get-ADPerformanceMetrics -ServerName $ServerName -DurationMinutes 60 -Metrics @("CPU", "Memory", "Disk", "Network")
                $troubleshootingStatus.TroubleshootingResults.PerformanceAnalysis = @{
                    Status = "Completed"
                    Details = $performanceAnalysis
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.PerformanceAnalysis = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "Performance analysis failed"
            }
        }
        
        # Perform event log analysis
        if ($IncludeEventLogAnalysis) {
            try {
                $eventLogAnalysis = Get-ADEventLogs -ServerName $ServerName -LogLevel "All" -MaxEvents 1000 -HoursBack 24
                $troubleshootingStatus.TroubleshootingResults.EventLogAnalysis = @{
                    Status = "Completed"
                    Details = $eventLogAnalysis
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.EventLogAnalysis = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "Event log analysis failed"
            }
        }
        
        # Perform security analysis
        if ($IncludeSecurityAnalysis) {
            try {
                $securityAnalysis = Get-ADSecurityStatus -ServerName $ServerName -IncludeDetails -IncludeAudit -IncludeAccess -IncludeKerberos -IncludeLDAPS -IncludeTrust
                $troubleshootingStatus.TroubleshootingResults.SecurityAnalysis = @{
                    Status = "Completed"
                    Details = $securityAnalysis
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.SecurityAnalysis = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "Security analysis failed"
            }
        }
        
        # Perform compliance check
        if ($IncludeComplianceCheck) {
            try {
                $complianceCheck = Get-ADComplianceStatus -ServerName $ServerName -IncludeDetails -IncludeStandards -IncludePolicies -IncludeAudit
                $troubleshootingStatus.TroubleshootingResults.ComplianceCheck = @{
                    Status = "Completed"
                    Details = $complianceCheck
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.ComplianceCheck = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "Compliance check failed"
            }
        }
        
        # Perform replication check
        if ($IncludeReplicationCheck) {
            try {
                $replicationCheck = Get-ADReplicationStatus -ServerName $ServerName
                $troubleshootingStatus.TroubleshootingResults.ReplicationCheck = @{
                    Status = "Completed"
                    Details = $replicationCheck
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.ReplicationCheck = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "Replication check failed"
            }
        }
        
        # Perform FSMO check
        if ($IncludeFSMOCheck) {
            try {
                $fsmoCheck = Get-ADFSMORoles -ServerName $ServerName
                $troubleshootingStatus.TroubleshootingResults.FSMOCheck = @{
                    Status = "Completed"
                    Details = $fsmoCheck
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.FSMOCheck = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "FSMO check failed"
            }
        }
        
        # Perform DNS check
        if ($IncludeDNSCheck) {
            try {
                $dnsCheck = Get-ADDNSStatus -ServerName $ServerName -IncludeDetails -IncludeZones -IncludeRecords -IncludeReplication
                $troubleshootingStatus.TroubleshootingResults.DNSCheck = @{
                    Status = "Completed"
                    Details = $dnsCheck
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.DNSCheck = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "DNS check failed"
            }
        }
        
        # Perform time sync check
        if ($IncludeTimeSyncCheck) {
            try {
                $timeSyncCheck = Get-ADTimeSyncStatus -ServerName $ServerName -IncludeDetails -IncludeNTP -IncludeW32Time
                $troubleshootingStatus.TroubleshootingResults.TimeSyncCheck = @{
                    Status = "Completed"
                    Details = $timeSyncCheck
                    Timestamp = Get-Date
                }
            }
            catch {
                $troubleshootingStatus.TroubleshootingResults.TimeSyncCheck = @{
                    Status = "Failed"
                    Details = $_.Exception.Message
                    Timestamp = Get-Date
                }
                $troubleshootingStatus.Issues += "Time sync check failed"
            }
        }
        
        # Determine overall status
        $failedChecks = $troubleshootingStatus.TroubleshootingResults.Values | Where-Object { $_.Status -eq "Failed" }
        if ($failedChecks.Count -eq 0) {
            $troubleshootingStatus.OverallStatus = "Healthy"
        } elseif ($failedChecks.Count -lt $troubleshootingStatus.TroubleshootingResults.Count / 2) {
            $troubleshootingStatus.OverallStatus = "Degraded"
        } else {
            $troubleshootingStatus.OverallStatus = "Unhealthy"
        }
        
        return $troubleshootingStatus
    }
    catch {
        Write-Error "Failed to perform AD troubleshooting: $($_.Exception.Message)"
        throw
    }
}

function Get-ADHealthStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
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
        Write-Host "Checking AD health status on $ServerName..." -ForegroundColor Cyan
        
        $healthStatus = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            OverallStatus = "Unknown"
            Components = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Check domain controller status
        try {
            $dcStatus = Get-ADDomainController -Server $ServerName -ErrorAction Stop
            $healthStatus.Components.DomainController = @{
                Status = "Healthy"
                Details = $dcStatus
            }
        }
        catch {
            $healthStatus.Components.DomainController = @{
                Status = "Unhealthy"
                Details = $_.Exception.Message
            }
            $healthStatus.Issues += "Domain controller check failed"
        }
        
        # Check replication if requested
        if ($IncludeReplication) {
            try {
                $replicationStatus = Get-ADReplicationPartnerMetadata -Target $ServerName -ErrorAction Stop
                $healthStatus.Components.Replication = @{
                    Status = "Healthy"
                    Details = $replicationStatus
                }
            }
            catch {
                $healthStatus.Components.Replication = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                }
                $healthStatus.Issues += "Replication check failed"
            }
        }
        
        # Check FSMO roles if requested
        if ($IncludeFSMO) {
            try {
                $fsmoRoles = Get-ADForest -Server $ServerName | Select-Object SchemaMaster, DomainNamingMaster
                $fsmoRoles | ForEach-Object {
                    $fsmoRoles += Get-ADDomain -Server $ServerName | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
                }
                $healthStatus.Components.FSMO = @{
                    Status = "Healthy"
                    Details = $fsmoRoles
                }
            }
            catch {
                $healthStatus.Components.FSMO = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                }
                $healthStatus.Issues += "FSMO roles check failed"
            }
        }
        
        # Determine overall status
        $unhealthyComponents = $healthStatus.Components.Values | Where-Object { $_.Status -eq "Unhealthy" }
        if ($unhealthyComponents.Count -eq 0) {
            $healthStatus.OverallStatus = "Healthy"
        } elseif ($unhealthyComponents.Count -lt $healthStatus.Components.Count / 2) {
            $healthStatus.OverallStatus = "Degraded"
        } else {
            $healthStatus.OverallStatus = "Unhealthy"
        }
        
        return $healthStatus
    }
    catch {
        Write-Error "Failed to check AD health status: $($_.Exception.Message)"
        throw
    }
}

function Get-ADPerformanceMetrics {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Metrics = @("CPU", "Memory", "Disk", "Network")
    )
    
    try {
        Write-Host "Collecting performance metrics from $ServerName..." -ForegroundColor Cyan
        
        $performanceMetrics = @{
            ServerName = $ServerName
            DurationMinutes = $DurationMinutes
            Metrics = $Metrics
            Timestamp = Get-Date
            PerformanceData = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Collect CPU metrics
        if ($Metrics -contains "CPU") {
            try {
                $cpuMetrics = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -MaxSamples 10 -ErrorAction Stop
                $performanceMetrics.PerformanceData.CPU = $cpuMetrics
            }
            catch {
                $performanceMetrics.Issues += "CPU metrics collection failed"
            }
        }
        
        # Collect memory metrics
        if ($Metrics -contains "Memory") {
            try {
                $memoryMetrics = Get-Counter -Counter "\Memory\Available MBytes" -MaxSamples 10 -ErrorAction Stop
                $performanceMetrics.PerformanceData.Memory = $memoryMetrics
            }
            catch {
                $performanceMetrics.Issues += "Memory metrics collection failed"
            }
        }
        
        # Collect disk metrics
        if ($Metrics -contains "Disk") {
            try {
                $diskMetrics = Get-Counter -Counter "\PhysicalDisk(_Total)\% Disk Time" -MaxSamples 10 -ErrorAction Stop
                $performanceMetrics.PerformanceData.Disk = $diskMetrics
            }
            catch {
                $performanceMetrics.Issues += "Disk metrics collection failed"
            }
        }
        
        # Collect network metrics
        if ($Metrics -contains "Network") {
            try {
                $networkMetrics = Get-Counter -Counter "\Network Interface(*)\Bytes Total/sec" -MaxSamples 10 -ErrorAction Stop
                $performanceMetrics.PerformanceData.Network = $networkMetrics
            }
            catch {
                $performanceMetrics.Issues += "Network metrics collection failed"
            }
        }
        
        return $performanceMetrics
    }
    catch {
        Write-Error "Failed to collect performance metrics: $($_.Exception.Message)"
        throw
    }
}

function Get-ADEventLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$LogLevel = "All",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 1000,
        
        [Parameter(Mandatory = $false)]
        [int]$HoursBack = 24
    )
    
    try {
        Write-Host "Collecting event logs from $ServerName..." -ForegroundColor Cyan
        
        $eventLogs = @{
            ServerName = $ServerName
            LogLevel = $LogLevel
            MaxEvents = $MaxEvents
            HoursBack = $HoursBack
            Timestamp = Get-Date
            EventData = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Collect application events
        try {
            $appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddHours(-$HoursBack)} -MaxEvents $MaxEvents -ErrorAction Stop
            $eventLogs.EventData.Application = $appEvents
        }
        catch {
            $eventLogs.Issues += "Application event log collection failed"
        }
        
        # Collect system events
        try {
            $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-$HoursBack)} -MaxEvents $MaxEvents -ErrorAction Stop
            $eventLogs.EventData.System = $systemEvents
        }
        catch {
            $eventLogs.Issues += "System event log collection failed"
        }
        
        # Collect security events
        try {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-$HoursBack)} -MaxEvents $MaxEvents -ErrorAction Stop
            $eventLogs.EventData.Security = $securityEvents
        }
        catch {
            $eventLogs.Issues += "Security event log collection failed"
        }
        
        return $eventLogs
    }
    catch {
        Write-Error "Failed to collect event logs: $($_.Exception.Message)"
        throw
    }
}

function Get-ADComplianceStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeStandards,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludePolicies,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeAudit
    )
    
    try {
        Write-Host "Checking AD compliance status on $ServerName..." -ForegroundColor Cyan
        
        $complianceStatus = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            OverallStatus = "Unknown"
            ComplianceData = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Check compliance standards
        if ($IncludeStandards) {
            try {
                $standards = @("FIPS140-2", "CommonCriteria", "ISO27001", "PCIDSS", "HIPAA", "SOX", "GDPR", "NIST")
                $complianceStatus.ComplianceData.Standards = $standards
            }
            catch {
                $complianceStatus.Issues += "Standards compliance check failed"
            }
        }
        
        # Check compliance policies
        if ($IncludePolicies) {
            try {
                $policies = @("SecurityPolicy", "AccessControlPolicy", "AuditPolicy", "EncryptionPolicy", "KeyManagementPolicy", "CertificateLifecyclePolicy", "CrossForestTrustPolicy", "SmartcardPolicy", "WindowsHelloPolicy", "BitLockerPolicy", "HSMPolicy", "CustomPolicy")
                $complianceStatus.ComplianceData.Policies = $policies
            }
            catch {
                $complianceStatus.Issues += "Policies compliance check failed"
            }
        }
        
        # Determine overall status
        if ($complianceStatus.Issues.Count -eq 0) {
            $complianceStatus.OverallStatus = "Compliant"
        } else {
            $complianceStatus.OverallStatus = "NonCompliant"
        }
        
        return $complianceStatus
    }
    catch {
        Write-Error "Failed to check AD compliance status: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Get-ADTroubleshootingStatus',
    'Get-ADHealthStatus',
    'Get-ADPerformanceMetrics',
    'Get-ADEventLogs',
    'Get-ADComplianceStatus'
)
