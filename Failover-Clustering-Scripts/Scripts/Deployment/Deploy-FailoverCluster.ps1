#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Windows Failover Cluster

.DESCRIPTION
    Main deployment script for Windows Failover Clustering solution.
    This script deploys a complete failover cluster with all 35 enterprise scenarios.

.PARAMETER ClusterName
    Name of the cluster to create

.PARAMETER Nodes
    Array of node names to include in the cluster

.PARAMETER QuorumType
    Type of quorum to use

.PARAMETER WitnessShare
    File share path for quorum witness

.PARAMETER CloudWitnessAccountName
    Azure storage account name for cloud witness

.PARAMETER CloudWitnessEndpoint
    Azure storage endpoint for cloud witness

.PARAMETER CloudWitnessKey
    Azure storage key for cloud witness

.PARAMETER StaticIPAddress
    Static IP address for the cluster

.PARAMETER ManagementPoint
    Management point for the cluster

.PARAMETER SecurityLevel
    Security level to apply

.PARAMETER ComplianceStandard
    Compliance standard to follow

.PARAMETER MonitoringLevel
    Monitoring level to configure

.PARAMETER AlertMethods
    Alert methods to configure

.PARAMETER Recipients
    Alert recipients

.PARAMETER DeployScenarios
    Array of enterprise scenarios to deploy

.PARAMETER Force
    Force deployment without confirmation

.EXAMPLE
    .\Deploy-FailoverCluster.ps1 -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeMajority"

.EXAMPLE
    .\Deploy-FailoverCluster.ps1 -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness" -SecurityLevel "High" -ComplianceStandard "CIS"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClusterName,

    [Parameter(Mandatory = $true)]
    [string[]]$Nodes,

    [Parameter(Mandatory = $false)]
    [ValidateSet("NodeMajority", "NodeAndDiskMajority", "NodeAndFileShareMajority", "NodeAndCloudMajority")]
    [string]$QuorumType = "NodeMajority",

    [Parameter(Mandatory = $false)]
    [string]$WitnessShare,

    [Parameter(Mandatory = $false)]
    [string]$CloudWitnessAccountName,

    [Parameter(Mandatory = $false)]
    [string]$CloudWitnessEndpoint,

    [Parameter(Mandatory = $false)]
    [string]$CloudWitnessKey,

    [Parameter(Mandatory = $false)]
    [string]$StaticIPAddress,

    [Parameter(Mandatory = $false)]
    [string]$ManagementPoint,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$SecurityLevel = "High",

    [Parameter(Mandatory = $false)]
    [ValidateSet("CIS", "NIST", "DoD", "FedRAMP", "Custom")]
    [string]$ComplianceStandard = "CIS",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Enhanced", "Advanced")]
    [string]$MonitoringLevel = "Advanced",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Email", "Webhook", "SNMP", "Slack", "Teams")]
    [string[]]$AlertMethods = @("Email"),

    [Parameter(Mandatory = $false)]
    [string[]]$Recipients = @("admin@contoso.com"),

    [Parameter(Mandatory = $false)]
    [int[]]$DeployScenarios = @(1, 2, 3, 4, 5),

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Script configuration
$scriptConfig = @{
    ScriptName = "Deploy-FailoverCluster"
    Version = "1.0.0"
    Author = "Adrian Johnson (adrian207@gmail.com)"
    StartTime = Get-Date
    ClusterName = $ClusterName
    Nodes = $Nodes
    QuorumType = $QuorumType
    SecurityLevel = $SecurityLevel
    ComplianceStandard = $ComplianceStandard
    MonitoringLevel = $MonitoringLevel
    DeployScenarios = $DeployScenarios
}

# Logging function
function Write-DeploymentLog {
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
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-DeploymentLog "Starting Windows Failover Cluster deployment" "Info"
    Write-DeploymentLog "Cluster Name: $ClusterName" "Info"
    Write-DeploymentLog "Nodes: $($Nodes -join ', ')" "Info"
    Write-DeploymentLog "Quorum Type: $QuorumType" "Info"
    Write-DeploymentLog "Security Level: $SecurityLevel" "Info"
    Write-DeploymentLog "Compliance Standard: $ComplianceStandard" "Info"
    Write-DeploymentLog "Monitoring Level: $MonitoringLevel" "Info"
    Write-DeploymentLog "Deploy Scenarios: $($DeployScenarios -join ', ')" "Info"

    # Import required modules
    Write-DeploymentLog "Importing required modules..." "Info"
    
    $modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $modulesPath = Join-Path $modulePath "Modules"
    
    Import-Module "$modulesPath\Cluster-Core.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Security.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Monitoring.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Troubleshooting.psm1" -Force -ErrorAction Stop
    
    Write-DeploymentLog "Modules imported successfully" "Success"

    # Validate prerequisites
    Write-DeploymentLog "Validating prerequisites..." "Info"
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 or later is required"
    }
    
    # Check Windows version
    $osInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
    if ($osInfo.WindowsVersion -lt "10.0.14393") {
        throw "Windows Server 2016 or later is required"
    }
    
    # Check Failover Clustering feature
    $clusteringFeature = Get-WindowsFeature -Name "Failover-Clustering" -ErrorAction Stop
    if ($clusteringFeature.InstallState -ne "Installed") {
        throw "Failover Clustering feature is not installed"
    }
    
    # Validate nodes
    foreach ($node in $Nodes) {
        if (!(Test-Connection -ComputerName $node -Count 1 -Quiet)) {
            throw "Node $node is not reachable"
        }
        
        # Check if Failover Clustering is installed on node
        $nodeFeature = Invoke-Command -ComputerName $node -ScriptBlock { Get-WindowsFeature -Name "Failover-Clustering" } -ErrorAction Stop
        if ($nodeFeature.InstallState -ne "Installed") {
            throw "Failover Clustering feature is not installed on node $node"
        }
    }
    
    Write-DeploymentLog "Prerequisites validated successfully" "Success"

    # Create failover cluster
    Write-DeploymentLog "Creating failover cluster..." "Info"
    
    $clusterParams = @{
        ClusterName = $ClusterName
        Nodes = $Nodes
        QuorumType = $QuorumType
        StaticIPAddress = $StaticIPAddress
        ManagementPoint = $ManagementPoint
        Force = $Force
    }
    
    if ($WitnessShare) {
        $clusterParams.WitnessShare = $WitnessShare
    }
    
    if ($CloudWitnessAccountName -and $CloudWitnessEndpoint -and $CloudWitnessKey) {
        $clusterParams.CloudWitnessAccountName = $CloudWitnessAccountName
        $clusterParams.CloudWitnessEndpoint = $CloudWitnessEndpoint
        $clusterParams.CloudWitnessKey = $CloudWitnessKey
    }
    
    $cluster = New-FailoverCluster @clusterParams
    
    if ($cluster) {
        Write-DeploymentLog "Failover cluster created successfully" "Success"
    } else {
        throw "Failed to create failover cluster"
    }

    # Apply security baseline
    Write-DeploymentLog "Applying security baseline..." "Info"
    
    $securityParams = @{
        ClusterName = $ClusterName
        BaselineName = "$ComplianceStandard-$SecurityLevel"
        ComplianceStandard = $ComplianceStandard
        SecurityLevel = $SecurityLevel
        IncludeNodes = $true
        IncludeCluster = $true
    }
    
    $securityConfig = Set-ClusterSecurityBaseline @securityParams
    
    if ($securityConfig) {
        Write-DeploymentLog "Security baseline applied successfully" "Success"
    } else {
        Write-DeploymentLog "Failed to apply security baseline" "Warning"
    }

    # Configure monitoring
    Write-DeploymentLog "Configuring monitoring..." "Info"
    
    $monitoringParams = @{
        ClusterName = $ClusterName
        MonitoringLevel = $MonitoringLevel
        MonitoringInterval = 5
        LogRetention = 30
        LogLocation = "C:\ClusterMonitoring"
    }
    
    $monitoringConfig = Set-ClusterMonitoring @monitoringParams
    
    if ($monitoringConfig) {
        Write-DeploymentLog "Monitoring configured successfully" "Success"
    } else {
        Write-DeploymentLog "Failed to configure monitoring" "Warning"
    }

    # Configure alerting
    Write-DeploymentLog "Configuring alerting..." "Info"
    
    $alertingParams = @{
        ClusterName = $ClusterName
        AlertMethods = $AlertMethods
        Recipients = $Recipients
    }
    
    $alertingConfig = Set-ClusterAlerting @alertingParams
    
    if ($alertingConfig) {
        Write-DeploymentLog "Alerting configured successfully" "Success"
    } else {
        Write-DeploymentLog "Failed to configure alerting" "Warning"
    }

    # Deploy enterprise scenarios
    if ($DeployScenarios.Count -gt 0) {
        Write-DeploymentLog "Deploying enterprise scenarios..." "Info"
        
        $scenariosScript = Join-Path $modulePath "Scripts\Enterprise-Scenarios\Deploy-ClusterEnterpriseScenarios.ps1"
        
        if (Test-Path $scenariosScript) {
            foreach ($scenarioNumber in $DeployScenarios) {
                Write-DeploymentLog "Deploying scenario $scenarioNumber..." "Info"
                
                try {
                    & $scenariosScript -ScenarioNumber $scenarioNumber -ClusterName $ClusterName -Force:$Force
                    Write-DeploymentLog "Scenario $scenarioNumber deployed successfully" "Success"
                }
                catch {
                    Write-DeploymentLog "Failed to deploy scenario $scenarioNumber`: $($_.Exception.Message)" "Warning"
                }
            }
        } else {
            Write-DeploymentLog "Enterprise scenarios script not found: $scenariosScript" "Warning"
        }
    }

    # Run initial diagnostics
    Write-DeploymentLog "Running initial diagnostics..." "Info"
    
    try {
        $diagnostics = Test-ClusterDiagnostics -ClusterName $ClusterName -DiagnosticLevel "Basic"
        
        if ($diagnostics.OverallStatus -eq "Pass") {
            Write-DeploymentLog "Initial diagnostics passed" "Success"
        } else {
            Write-DeploymentLog "Initial diagnostics found issues: $($diagnostics.Issues -join '; ')" "Warning"
        }
    }
    catch {
        Write-DeploymentLog "Failed to run initial diagnostics: $($_.Exception.Message)" "Warning"
    }

    # Generate deployment report
    Write-DeploymentLog "Generating deployment report..." "Info"
    
    $reportPath = "C:\ClusterDeployment\Reports\DeploymentReport_$ClusterName_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportDir = Split-Path $reportPath -Parent
    
    if (!(Test-Path $reportDir)) {
        New-Item -Path $reportDir -ItemType Directory -Force
    }
    
    try {
        Get-ClusterReport -ClusterName $ClusterName -ReportType "Comprehensive" -OutputPath $reportPath -Format "HTML"
        Write-DeploymentLog "Deployment report generated: $reportPath" "Success"
    }
    catch {
        Write-DeploymentLog "Failed to generate deployment report: $($_.Exception.Message)" "Warning"
    }

    # Final validation
    Write-DeploymentLog "Running final validation..." "Info"
    
    try {
        $clusterStatus = Get-ClusterStatus -ClusterName $ClusterName -IncludeDetails
        
        if ($clusterStatus.OverallHealth -eq "Healthy") {
            Write-DeploymentLog "Final validation passed - cluster is healthy" "Success"
        } else {
            Write-DeploymentLog "Final validation found issues: $($clusterStatus.Issues -join '; ')" "Warning"
        }
    }
    catch {
        Write-DeploymentLog "Failed to run final validation: $($_.Exception.Message)" "Warning"
    }

    # Deployment summary
    $scriptConfig.EndTime = Get-Date
    $scriptConfig.Duration = ($scriptConfig.EndTime - $scriptConfig.StartTime).TotalMinutes
    
    Write-DeploymentLog "Windows Failover Cluster deployment completed" "Success"
    Write-DeploymentLog "Deployment Duration: $([math]::Round($scriptConfig.Duration, 2)) minutes" "Info"
    Write-DeploymentLog "Cluster Name: $ClusterName" "Info"
    Write-DeploymentLog "Nodes: $($Nodes -join ', ')" "Info"
    Write-DeploymentLog "Quorum Type: $QuorumType" "Info"
    Write-DeploymentLog "Security Level: $SecurityLevel" "Info"
    Write-DeploymentLog "Compliance Standard: $ComplianceStandard" "Info"
    Write-DeploymentLog "Monitoring Level: $MonitoringLevel" "Info"
    Write-DeploymentLog "Deployed Scenarios: $($DeployScenarios -join ', ')" "Info"
    
    if (Test-Path $reportPath) {
        Write-DeploymentLog "Deployment Report: $reportPath" "Info"
    }
    
    Write-DeploymentLog "Next Steps:" "Info"
    Write-DeploymentLog "1. Review the deployment report" "Info"
    Write-DeploymentLog "2. Test cluster functionality" "Info"
    Write-DeploymentLog "3. Configure additional resources as needed" "Info"
    Write-DeploymentLog "4. Set up regular monitoring and maintenance" "Info"
    Write-DeploymentLog "5. Document cluster configuration" "Info"
    
    return $scriptConfig
}
catch {
    Write-DeploymentLog "Deployment failed: $($_.Exception.Message)" "Error"
    Write-DeploymentLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    
    # Attempt to clean up on failure
    try {
        Write-DeploymentLog "Attempting to clean up failed deployment..." "Warning"
        
        if (Get-Cluster -Name $ClusterName -ErrorAction SilentlyContinue) {
            Remove-Cluster -Name $ClusterName -Force -ErrorAction SilentlyContinue
            Write-DeploymentLog "Cluster removed during cleanup" "Info"
        }
    }
    catch {
        Write-DeploymentLog "Cleanup failed: $($_.Exception.Message)" "Warning"
    }
    
    throw
}
finally {
    Write-DeploymentLog "Deployment script completed" "Info"
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script deploys a complete Windows Failover Cluster with all 35 enterprise scenarios.
    It includes security baselines, monitoring, alerting, and comprehensive diagnostics.
    
    Prerequisites:
    - Windows Server 2016 or later
    - PowerShell 5.1 or later
    - Failover Clustering feature installed
    - Administrator privileges
    - Network connectivity between nodes
    
    Enterprise Scenarios:
    1. High Availability for File Services
    2. Highly Available Hyper-V Virtual Machines
    3. SQL Server Always-On Failover Cluster Instances (FCI)
    4. Cluster Shared Volumes (CSV)
    5. Stretch Clusters / Multi-Site Disaster Recovery
    6. Cluster-Aware Updating (CAU)
    7. Failover Clustering with Storage Spaces Direct (S2D)
    8. Highly Available DHCP / DNS
    9. Clustered Print Servers
    10. File Server for Application Data
    11. iSCSI Target Server Clustering
    12. NFS Cluster for UNIX/Linux Clients
    13. Active/Active Load Balancing
    14. Active/Passive Role Failover
    15. Heartbeat and Witness Configuration
    16. Cluster Validation Wizard
    17. Cloud Witness for Hybrid Clusters
    18. VM Resiliency with Fault Domains
    19. Guest Clustering
    20. Cluster-Aware Backup and Recovery
    21. High-Availability Certificate Authority
    22. Hyper-V Replica + Failover Cluster Integration
    23. Application Availability via Generic Roles
    24. Clustered MSMQ (Message Queuing)
    25. File Server for User Profile Disks (UPDs) and FSLogix
    26. Failover Clustering for Keyfactor or CA Database
    27. PowerShell and REST API Cluster Management
    28. Multi-Subnet Clusters
    29. Rolling Upgrades Across OS Versions
    30. SIEM and Monitoring Integration
    31. Cluster-Aware Storage Replica
    32. Quorum File Share Witness in Edge Environments
    33. Hyper-V Shielded VM Cluster Integration
    34. Tiered Application Clusters
    35. Test/Dev Sandbox for HA Workloads
#>
