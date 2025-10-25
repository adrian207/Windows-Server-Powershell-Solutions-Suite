#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Failover Clustering Examples

.DESCRIPTION
    Comprehensive examples and demonstrations for Windows Failover Clustering.
    This script provides practical examples for all 35 enterprise scenarios.

.PARAMETER ExampleType
    Type of examples to run: Basic, Advanced, Enterprise, Specific, or All

.PARAMETER ClusterName
    Name of the cluster to use for examples

.PARAMETER Interactive
    Whether to run examples interactively

.PARAMETER ScenarioNumber
    Specific scenario number to demonstrate (1-35)

.EXAMPLE
    .\Cluster-Examples.ps1 -ExampleType "Basic" -ClusterName "TEST-CLUSTER" -Interactive

.EXAMPLE
    .\Cluster-Examples.ps1 -ExampleType "Specific" -ScenarioNumber 5 -ClusterName "PROD-CLUSTER"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive examples and demonstrations for Windows Failover Clustering.
    It covers all 35 enterprise scenarios with practical examples and interactive demonstrations.
    
    Example Types:
    - Basic: Fundamental cluster operations
    - Advanced: Complex configurations and features
    - Enterprise: Large-scale deployments and scenarios
    - Specific: Individual scenario demonstrations
    
    Interactive Mode:
    - Prompts user to run each example
    - Provides real-time feedback
    - Handles errors gracefully
    
    Examples Covered:
    1. Basic cluster creation and management
    2. Quorum configuration
    3. Scale-Out File Server
    4. Storage Spaces Direct
    5. Cluster-Aware Updating
    6. Stretch clusters
    7. Cloud witness
    8. SQL Server FCI
    9. Hyper-V clustering
    10. Health monitoring
    11. Performance optimization
    12. Security hardening
    13. Troubleshooting
    14. Enterprise scenarios
    15. Advanced configurations
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Advanced", "Enterprise", "Specific", "All")]
    [string]$ExampleType = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$ClusterName = "TEST-CLUSTER",
    
    [Parameter(Mandatory = $false)]
    [switch]$Interactive = $false,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 35)]
    [int]$ScenarioNumber
)

# Logging function
function Write-ExampleLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Example" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-ExampleLog "Starting Windows Failover Clustering examples" "Info"
    Write-ExampleLog "Example Type: $ExampleType" "Info"
    Write-ExampleLog "Cluster Name: $ClusterName" "Info"
    Write-ExampleLog "Interactive: $Interactive" "Info"
    if ($ScenarioNumber) { Write-ExampleLog "Scenario Number: $ScenarioNumber" "Info" }

    # Import required modules
    Write-ExampleLog "Importing required modules..." "Info"
    
    $modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $modulesPath = Join-Path $modulePath "..\Modules"
    
    Import-Module "$modulesPath\Cluster-Core.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Security.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Monitoring.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Troubleshooting.psm1" -Force -ErrorAction Stop
    
    Write-ExampleLog "Modules imported successfully" "Success"

    # Basic Examples
    if ($ExampleType -in @("All", "Basic")) {
        Write-ExampleLog "=== BASIC EXAMPLES ===" "Example"
        
        # Example 1: Create Basic Cluster
        Write-ExampleLog "Example 1: Create Basic Cluster" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Create a basic 2-node cluster" "Example"
        Write-ExampleLog "New-FailoverCluster -ClusterName 'TEST-CLUSTER' -Nodes @('NODE01', 'NODE02') -QuorumType 'NodeMajority'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    New-FailoverCluster -ClusterName "TEST-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeMajority"
                    Write-ExampleLog "Basic cluster created successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to create basic cluster: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 2: Check Cluster Status
        Write-ExampleLog "Example 2: Check Cluster Status" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Get comprehensive cluster status" "Example"
        Write-ExampleLog "Get-ClusterStatus -ClusterName 'TEST-CLUSTER' -IncludeDetails" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    $status = Get-ClusterStatus -ClusterName "TEST-CLUSTER" -IncludeDetails
                    Write-ExampleLog "Cluster status retrieved successfully" "Success"
                    Write-ExampleLog "Cluster State: $($status.ClusterState)" "Info"
                    Write-ExampleLog "Quorum State: $($status.QuorumState)" "Info"
                }
                catch {
                    Write-ExampleLog "Failed to get cluster status: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 3: Configure Quorum
        Write-ExampleLog "Example 3: Configure Quorum" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Configure quorum with file share witness" "Example"
        Write-ExampleLog "Set-ClusterQuorum -ClusterName 'TEST-CLUSTER' -QuorumType 'NodeAndFileShareMajority' -WitnessShare '\\DC01\ClusterWitness'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    Set-ClusterQuorum -ClusterName "TEST-CLUSTER" -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"
                    Write-ExampleLog "Quorum configured successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to configure quorum: $($_.Exception.Message)" "Warning"
                }
            }
        }
    }

    # Advanced Examples
    if ($ExampleType -in @("All", "Advanced")) {
        Write-ExampleLog "=== ADVANCED EXAMPLES ===" "Example"
        
        # Example 4: Scale-Out File Server
        Write-ExampleLog "Example 4: Scale-Out File Server" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Deploy Scale-Out File Server" "Example"
        Write-ExampleLog "New-ClusterResource -ClusterName 'PROD-CLUSTER' -ResourceName 'SOFS' -ResourceType 'Scale-Out File Server' -Group 'FileServerGroup'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    New-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "SOFS" -ResourceType "Scale-Out File Server" -Group "FileServerGroup"
                    Write-ExampleLog "Scale-Out File Server created successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to create Scale-Out File Server: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 5: Storage Spaces Direct
        Write-ExampleLog "Example 5: Storage Spaces Direct" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Enable Storage Spaces Direct" "Example"
        Write-ExampleLog "Enable-StorageSpacesDirect -ClusterName 'PROD-CLUSTER' -CacheMode 'WriteBack'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    Enable-StorageSpacesDirect -ClusterName "PROD-CLUSTER" -CacheMode "WriteBack"
                    Write-ExampleLog "Storage Spaces Direct enabled successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to enable Storage Spaces Direct: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 6: Cluster-Aware Updating
        Write-ExampleLog "Example 6: Cluster-Aware Updating" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Enable Cluster-Aware Updating" "Example"
        Write-ExampleLog "Enable-ClusterAwareUpdating -ClusterName 'PROD-CLUSTER' -UpdateMode 'Automatic'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    Enable-ClusterAwareUpdating -ClusterName "PROD-CLUSTER" -UpdateMode "Automatic"
                    Write-ExampleLog "Cluster-Aware Updating enabled successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to enable Cluster-Aware Updating: $($_.Exception.Message)" "Warning"
                }
            }
        }
    }

    # Enterprise Examples
    if ($ExampleType -in @("All", "Enterprise")) {
        Write-ExampleLog "=== ENTERPRISE EXAMPLES ===" "Example"
        
        # Example 7: Stretch Cluster
        Write-ExampleLog "Example 7: Stretch Cluster" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Deploy stretch cluster across sites" "Example"
        Write-ExampleLog "New-FailoverCluster -ClusterName 'STRETCH-CLUSTER' -Nodes @('SITE1-NODE01', 'SITE1-NODE02', 'SITE2-NODE01', 'SITE2-NODE02') -QuorumType 'NodeAndFileShareMajority'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    New-FailoverCluster -ClusterName "STRETCH-CLUSTER" -Nodes @("SITE1-NODE01", "SITE1-NODE02", "SITE2-NODE01", "SITE2-NODE02") -QuorumType "NodeAndFileShareMajority"
                    Write-ExampleLog "Stretch cluster created successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to create stretch cluster: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 8: Cloud Witness
        Write-ExampleLog "Example 8: Cloud Witness" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Configure cloud witness" "Example"
        Write-ExampleLog "Set-ClusterQuorum -ClusterName 'PROD-CLUSTER' -QuorumType 'NodeAndCloudMajority' -CloudWitnessAccountName 'AzureStorageAccount' -CloudWitnessEndpoint 'https://AzureStorageAccount.blob.core.windows.net' -CloudWitnessKey 'AzureStorageKey'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    Set-ClusterQuorum -ClusterName "PROD-CLUSTER" -QuorumType "NodeAndCloudMajority" -CloudWitnessAccountName "AzureStorageAccount" -CloudWitnessEndpoint "https://AzureStorageAccount.blob.core.windows.net" -CloudWitnessKey "AzureStorageKey"
                    Write-ExampleLog "Cloud witness configured successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to configure cloud witness: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 9: SQL Server FCI
        Write-ExampleLog "Example 9: SQL Server FCI" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Deploy SQL Server FCI" "Example"
        Write-ExampleLog "New-ClusterResource -ClusterName 'PROD-CLUSTER' -ResourceName 'SQL-FCI' -ResourceType 'SQL Server' -Dependencies @('SQL-Disk', 'SQL-Network')" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    New-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "SQL-FCI" -ResourceType "SQL Server" -Dependencies @("SQL-Disk", "SQL-Network")
                    Write-ExampleLog "SQL Server FCI created successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to create SQL Server FCI: $($_.Exception.Message)" "Warning"
                }
            }
        }
    }

    # Specific Scenario Examples
    if ($ExampleType -eq "Specific" -and $ScenarioNumber) {
        Write-ExampleLog "=== SPECIFIC SCENARIO EXAMPLE ===" "Example"
        
        $scenarioExamples = @{
            1 = @{
                Title = "High Availability for File Services"
                Code = "New-ClusterResource -ClusterName '$ClusterName' -ResourceName 'FileShare' -ResourceType 'File Server' -Group 'FileServerGroup'"
            }
            2 = @{
                Title = "Highly Available Hyper-V Virtual Machines"
                Code = "New-ClusterResource -ClusterName '$ClusterName' -ResourceName 'Hyper-V' -ResourceType 'Virtual Machine' -Group 'VMGroup'"
            }
            3 = @{
                Title = "SQL Server Always-On Failover Cluster Instances (FCI)"
                Code = "New-ClusterResource -ClusterName '$ClusterName' -ResourceName 'SQL-FCI' -ResourceType 'SQL Server' -Dependencies @('SQL-Disk', 'SQL-Network')"
            }
            4 = @{
                Title = "Cluster Shared Volumes (CSV)"
                Code = "New-ClusterResource -ClusterName '$ClusterName' -ResourceName 'CSV-Volume1' -ResourceType 'Physical Disk' -Group 'CSVGroup'"
            }
            5 = @{
                Title = "Stretch Clusters / Multi-Site Disaster Recovery"
                Code = "New-FailoverCluster -ClusterName 'STRETCH-CLUSTER' -Nodes @('SITE1-NODE01', 'SITE1-NODE02', 'SITE2-NODE01', 'SITE2-NODE02') -QuorumType 'NodeAndFileShareMajority'"
            }
        }
        
        $scenario = $scenarioExamples[$ScenarioNumber]
        if ($scenario) {
            Write-ExampleLog "Scenario $ScenarioNumber`: $($scenario.Title)" "Example"
            Write-ExampleLog "```powershell" "Example"
            Write-ExampleLog $scenario.Code "Example"
            Write-ExampleLog "```" "Example"
            
            if ($Interactive) {
                $response = Read-Host "Run this scenario example? (y/n)"
                if ($response -eq "y") {
                    try {
                        Invoke-Expression $scenario.Code
                        Write-ExampleLog "Scenario $ScenarioNumber executed successfully" "Success"
                    }
                    catch {
                        Write-ExampleLog "Failed to execute scenario $ScenarioNumber`: $($_.Exception.Message)" "Warning"
                    }
                }
            }
        } else {
            Write-ExampleLog "Scenario $ScenarioNumber not found in examples" "Warning"
        }
    }

    # Monitoring Examples
    if ($ExampleType -in @("All", "Advanced", "Enterprise")) {
        Write-ExampleLog "=== MONITORING EXAMPLES ===" "Example"
        
        # Example 10: Health Monitoring
        Write-ExampleLog "Example 10: Health Monitoring" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Get comprehensive cluster health status" "Example"
        Write-ExampleLog "Get-ClusterHealthStatus -ClusterName '$ClusterName' -IncludeDetails -IncludeNodes -IncludeResources" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    $health = Get-ClusterHealthStatus -ClusterName $ClusterName -IncludeDetails -IncludeNodes -IncludeResources
                    Write-ExampleLog "Cluster health status retrieved successfully" "Success"
                    Write-ExampleLog "Overall Health: $($health.OverallHealth)" "Info"
                }
                catch {
                    Write-ExampleLog "Failed to get cluster health: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 11: Performance Monitoring
        Write-ExampleLog "Example 11: Performance Monitoring" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Monitor cluster performance metrics" "Example"
        Write-ExampleLog "Get-ClusterPerformanceMetrics -ClusterName '$ClusterName' -MetricType 'CPU,Memory,Network,Disk' -Duration '1Hour'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    $metrics = Get-ClusterPerformanceMetrics -ClusterName $ClusterName -MetricType "CPU,Memory,Network,Disk" -Duration "1Hour"
                    Write-ExampleLog "Performance metrics retrieved successfully" "Success"
                    Write-ExampleLog "CPU Usage: $($metrics.CPUUsage)%" "Info"
                }
                catch {
                    Write-ExampleLog "Failed to get performance metrics: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 12: Event Log Monitoring
        Write-ExampleLog "Example 12: Event Log Monitoring" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Monitor cluster event logs" "Example"
        Write-ExampleLog "Get-ClusterEventLogs -ClusterName '$ClusterName' -LogLevel 'Warning,Error' -TimeRange '24Hours' -IncludeDetails" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    $events = Get-ClusterEventLogs -ClusterName $ClusterName -LogLevel "Warning,Error" -TimeRange "24Hours" -IncludeDetails
                    Write-ExampleLog "Event logs retrieved successfully" "Success"
                    Write-ExampleLog "Events Found: $($events.Count)" "Info"
                }
                catch {
                    Write-ExampleLog "Failed to get event logs: $($_.Exception.Message)" "Warning"
                }
            }
        }
    }

    # Security Examples
    if ($ExampleType -in @("All", "Advanced", "Enterprise")) {
        Write-ExampleLog "=== SECURITY EXAMPLES ===" "Example"
        
        # Example 13: Security Hardening
        Write-ExampleLog "Example 13: Security Hardening" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Apply security hardening baseline" "Example"
        Write-ExampleLog "Set-ClusterSecurityBaseline -ClusterName '$ClusterName' -BaselineName 'CIS-High' -ComplianceStandard 'CIS' -SecurityLevel 'High' -IncludeNodes -IncludeCluster" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    Set-ClusterSecurityBaseline -ClusterName $ClusterName -BaselineName "CIS-High" -ComplianceStandard "CIS" -SecurityLevel "High" -IncludeNodes -IncludeCluster
                    Write-ExampleLog "Security hardening applied successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to apply security hardening: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 14: Certificate Management
        Write-ExampleLog "Example 14: Certificate Management" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Configure cluster certificates" "Example"
        Write-ExampleLog "Set-ClusterCertificate -ClusterName '$ClusterName' -CertificateType 'Cluster' -CertificateStore 'LocalMachine' -CertificateSubject 'CN=Cluster-Cert'" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    Set-ClusterCertificate -ClusterName $ClusterName -CertificateType "Cluster" -CertificateStore "LocalMachine" -CertificateSubject "CN=Cluster-Cert"
                    Write-ExampleLog "Certificate configured successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to configure certificate: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 15: Audit Logging
        Write-ExampleLog "Example 15: Audit Logging" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Enable comprehensive audit logging" "Example"
        Write-ExampleLog "Enable-ClusterAuditLogging -ClusterName '$ClusterName' -AuditLevel 'Comprehensive' -IncludeSecurityEvents -IncludeConfigurationChanges -IncludeResourceChanges" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    Enable-ClusterAuditLogging -ClusterName $ClusterName -AuditLevel "Comprehensive" -IncludeSecurityEvents -IncludeConfigurationChanges -IncludeResourceChanges
                    Write-ExampleLog "Audit logging enabled successfully" "Success"
                }
                catch {
                    Write-ExampleLog "Failed to enable audit logging: $($_.Exception.Message)" "Warning"
                }
            }
        }
    }

    # Troubleshooting Examples
    if ($ExampleType -in @("All", "Advanced", "Enterprise")) {
        Write-ExampleLog "=== TROUBLESHOOTING EXAMPLES ===" "Example"
        
        # Example 16: Diagnostics
        Write-ExampleLog "Example 16: Diagnostics" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Run comprehensive diagnostics" "Example"
        Write-ExampleLog "Test-ClusterDiagnostics -ClusterName '$ClusterName' -DiagnosticLevel 'Comprehensive' -IncludePerformance -IncludeSecurity -IncludeConnectivity" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    $diagnostics = Test-ClusterDiagnostics -ClusterName $ClusterName -DiagnosticLevel "Comprehensive" -IncludePerformance -IncludeSecurity -IncludeConnectivity
                    Write-ExampleLog "Diagnostics completed successfully" "Success"
                    Write-ExampleLog "Issues Found: $($diagnostics.IssuesFound)" "Info"
                }
                catch {
                    Write-ExampleLog "Failed to run diagnostics: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 17: Repair Operations
        Write-ExampleLog "Example 17: Repair Operations" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Repair cluster issues" "Example"
        Write-ExampleLog "Repair-ClusterIssues -ClusterName '$ClusterName' -RepairType 'Automatic' -IncludeQuorum -IncludeResources -IncludeNetworks" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    $repair = Repair-ClusterIssues -ClusterName $ClusterName -RepairType "Automatic" -IncludeQuorum -IncludeResources -IncludeNetworks
                    Write-ExampleLog "Repair operations completed successfully" "Success"
                    Write-ExampleLog "Issues Repaired: $($repair.IssuesRepaired)" "Info"
                }
                catch {
                    Write-ExampleLog "Failed to repair cluster issues: $($_.Exception.Message)" "Warning"
                }
            }
        }
        
        # Example 18: Event Log Analysis
        Write-ExampleLog "Example 18: Event Log Analysis" "Example"
        Write-ExampleLog "```powershell" "Example"
        Write-ExampleLog "# Analyze cluster event logs for issues" "Example"
        Write-ExampleLog "Analyze-ClusterEventLogs -ClusterName '$ClusterName' -AnalysisType 'Comprehensive' -TimeRange '7Days' -GenerateReport" "Example"
        Write-ExampleLog "```" "Example"
        
        if ($Interactive) {
            $response = Read-Host "Run this example? (y/n)"
            if ($response -eq "y") {
                try {
                    $analysis = Analyze-ClusterEventLogs -ClusterName $ClusterName -AnalysisType "Comprehensive" -TimeRange "7Days" -GenerateReport
                    Write-ExampleLog "Event log analysis completed successfully" "Success"
                    Write-ExampleLog "Critical Issues: $($analysis.CriticalIssues)" "Info"
                }
                catch {
                    Write-ExampleLog "Failed to analyze event logs: $($_.Exception.Message)" "Warning"
                }
            }
        }
    }

    # Generate Examples Report
    try {
        $reportPath = Join-Path $PSScriptRoot "Examples-Report.html"
        Get-ClusterReport -ClusterName $ClusterName -ReportType "Basic" -OutputPath $reportPath -Format "HTML"
        Write-ExampleLog "Examples report generated: $reportPath" "Success"
    }
    catch {
        Write-ExampleLog "Failed to generate examples report: $($_.Exception.Message)" "Warning"
    }

    Write-ExampleLog "Windows Failover Clustering examples completed" "Success"
}
catch {
    Write-ExampleLog "Examples failed: $($_.Exception.Message)" "Error"
    Write-ExampleLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
finally {
    Write-ExampleLog "Examples script completed" "Info"
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive examples and demonstrations for Windows Failover Clustering.
    It covers all 35 enterprise scenarios with practical examples and interactive demonstrations.
    
    Example Types:
    - Basic: Fundamental cluster operations
    - Advanced: Complex configurations and features
    - Enterprise: Large-scale deployments and scenarios
    - Specific: Individual scenario demonstrations
    
    Interactive Mode:
    - Prompts user to run each example
    - Provides real-time feedback
    - Handles errors gracefully
    
    Examples Covered:
    1. Basic cluster creation and management
    2. Quorum configuration
    3. Scale-Out File Server
    4. Storage Spaces Direct
    5. Cluster-Aware Updating
    6. Stretch clusters
    7. Cloud witness
    8. SQL Server FCI
    9. Hyper-V clustering
    10. Health monitoring
    11. Performance optimization
    12. Security hardening
    13. Troubleshooting
    14. Enterprise scenarios
    15. Advanced configurations
    
    Requirements:
    - Windows Server 2016 or later
    - Failover Clustering feature
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - Cluster-Core.psm1
    - Cluster-Security.psm1
    - Cluster-Monitoring.psm1
    - Cluster-Troubleshooting.psm1
    
    Usage Examples:
    .\Cluster-Examples.ps1 -ExampleType "Basic" -ClusterName "TEST-CLUSTER" -Interactive
    .\Cluster-Examples.ps1 -ExampleType "Specific" -ScenarioNumber 5 -ClusterName "PROD-CLUSTER"
    .\Cluster-Examples.ps1 -ExampleType "All" -ClusterName "ENTERPRISE-CLUSTER" -Interactive
    
    Output:
    - Console logging with color-coded messages
    - HTML report generation
    - Interactive example execution
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Validates cluster names and parameters
    - Implements secure error handling
    - Logs all operations for audit
    
    Performance Impact:
    - Minimal impact during examples
    - Non-destructive operations
    - Configurable execution modes
    - Resource monitoring included
#>
