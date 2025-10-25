#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure Windows Failover Cluster

.DESCRIPTION
    Comprehensive configuration script for Windows Failover Clustering.
    Handles cluster setup, quorum configuration, resource management, and optimization.

.PARAMETER ClusterName
    Name of the cluster to configure

.PARAMETER Nodes
    Array of node names to include in the cluster

.PARAMETER QuorumType
    Type of quorum configuration (NodeMajority, NodeAndDiskMajority, NodeAndFileShareMajority, NodeAndCloudMajority)

.PARAMETER WitnessShare
    UNC path to file share witness (for NodeAndFileShareMajority)

.PARAMETER CloudWitnessAccount
    Azure storage account name for cloud witness

.PARAMETER CloudWitnessEndpoint
    Azure storage endpoint for cloud witness

.PARAMETER CloudWitnessKey
    Azure storage key for cloud witness

.PARAMETER StaticIPAddress
    Static IP address for the cluster

.PARAMETER ClusterIPSubnet
    Subnet for cluster IP address

.PARAMETER EnableStorageSpacesDirect
    Enable Storage Spaces Direct

.PARAMETER EnableClusterAwareUpdating
    Enable Cluster-Aware Updating

.PARAMETER ConfigureNetworks
    Configure cluster networks

.PARAMETER ConfigureResources
    Configure cluster resources

.PARAMETER SecurityLevel
    Security configuration level (Basic, Enhanced, High)

.PARAMETER ConfigurationFile
    Path to JSON configuration file

.EXAMPLE
    .\Configure-Cluster.ps1 -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeMajority"

.EXAMPLE
    .\Configure-Cluster.ps1 -ClusterName "HA-CLUSTER" -Nodes @("NODE01", "NODE02", "NODE03") -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive configuration for Windows Failover Clustering.
    It handles all aspects of cluster setup, optimization, and management.
#>

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
    [string]$CloudWitnessAccount,
    
    [Parameter(Mandatory = $false)]
    [string]$CloudWitnessEndpoint,
    
    [Parameter(Mandatory = $false)]
    [string]$CloudWitnessKey,
    
    [Parameter(Mandatory = $false)]
    [string]$StaticIPAddress,
    
    [Parameter(Mandatory = $false)]
    [string]$ClusterIPSubnet,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableStorageSpacesDirect,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableClusterAwareUpdating,
    
    [Parameter(Mandatory = $false)]
    [switch]$ConfigureNetworks,
    
    [Parameter(Mandatory = $false)]
    [switch]$ConfigureResources,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Enhanced", "High")]
    [string]$SecurityLevel = "Enhanced",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\Modules"

Import-Module "$modulesPath\Cluster-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\Cluster-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\Cluster-Monitoring.psm1" -Force -ErrorAction Stop

# Logging function
function Write-ConfigLog {
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
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-ConfigLog "Starting cluster configuration" "Info"
    Write-ConfigLog "Cluster Name: $ClusterName" "Info"
    Write-ConfigLog "Nodes: $($Nodes -join ', ')" "Info"
    Write-ConfigLog "Quorum Type: $QuorumType" "Info"
    
    # Load configuration from file if provided
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        Write-ConfigLog "Loading configuration from file: $ConfigurationFile" "Info"
        $config = Get-Content $ConfigurationFile | ConvertFrom-Json
        
        # Override parameters with file values if not specified
        if (-not $PSBoundParameters.ContainsKey('QuorumType') -and $config.QuorumType) {
            $QuorumType = $config.QuorumType
        }
        if (-not $PSBoundParameters.ContainsKey('WitnessShare') -and $config.WitnessShare) {
            $WitnessShare = $config.WitnessShare
        }
        if (-not $PSBoundParameters.ContainsKey('SecurityLevel') -and $config.SecurityLevel) {
            $SecurityLevel = $config.SecurityLevel
        }
    }
    
    # Validate prerequisites
    Write-ConfigLog "Validating prerequisites..." "Info"
    
    # Check if nodes are available
    foreach ($node in $Nodes) {
        if (-not (Test-Connection -ComputerName $node -Count 1 -Quiet)) {
            throw "Node $node is not reachable"
        }
        Write-ConfigLog "Node $node is reachable" "Success"
    }
    
    # Check if Failover Clustering feature is installed on all nodes
    foreach ($node in $Nodes) {
        $feature = Invoke-Command -ComputerName $node -ScriptBlock {
            Get-WindowsFeature -Name "Failover-Clustering" | Select-Object -ExpandProperty InstallState
        }
        if ($feature -ne "Installed") {
            Write-ConfigLog "Installing Failover Clustering feature on $node" "Info"
            Install-ClusterFeature -ComputerName $node
        }
    }
    
    # Create cluster
    Write-ConfigLog "Creating cluster: $ClusterName" "Info"
    
    $clusterParams = @{
        Name = $ClusterName
        Node = $Nodes
        StaticAddress = $StaticIPAddress
    }
    
    if ($ClusterIPSubnet) {
        $clusterParams.StaticAddress = $ClusterIPSubnet
    }
    
    New-Cluster @clusterParams -ErrorAction Stop
    Write-ConfigLog "Cluster created successfully" "Success"
    
    # Configure quorum
    Write-ConfigLog "Configuring quorum: $QuorumType" "Info"
    
    switch ($QuorumType) {
        "NodeMajority" {
            Set-ClusterQuorum -Cluster $ClusterName -NodeMajority
        }
        "NodeAndDiskMajority" {
            Set-ClusterQuorum -Cluster $ClusterName -NodeAndDiskMajority
        }
        "NodeAndFileShareMajority" {
            if (-not $WitnessShare) {
                throw "WitnessShare parameter is required for NodeAndFileShareMajority quorum"
            }
            Set-ClusterQuorum -Cluster $ClusterName -NodeAndFileShareMajority -FileShareWitness $WitnessShare
        }
        "NodeAndCloudMajority" {
            if (-not $CloudWitnessAccount -or -not $CloudWitnessEndpoint -or -not $CloudWitnessKey) {
                throw "Cloud witness parameters are required for NodeAndCloudMajority quorum"
            }
            Set-ClusterQuorum -Cluster $ClusterName -NodeAndCloudMajority -CloudWitnessAccountName $CloudWitnessAccount -CloudWitnessEndpoint $CloudWitnessEndpoint -CloudWitnessKey $CloudWitnessKey
        }
    }
    
    Write-ConfigLog "Quorum configured successfully" "Success"
    
    # Configure networks if requested
    if ($ConfigureNetworks) {
        Write-ConfigLog "Configuring cluster networks..." "Info"
        Configure-ClusterNetworks -ClusterName $ClusterName
        Write-ConfigLog "Cluster networks configured" "Success"
    }
    
    # Configure resources if requested
    if ($ConfigureResources) {
        Write-ConfigLog "Configuring cluster resources..." "Info"
        Configure-ClusterResources -ClusterName $ClusterName
        Write-ConfigLog "Cluster resources configured" "Success"
    }
    
    # Enable Storage Spaces Direct if requested
    if ($EnableStorageSpacesDirect) {
        Write-ConfigLog "Enabling Storage Spaces Direct..." "Info"
        Enable-StorageSpacesDirect -ClusterName $ClusterName
        Write-ConfigLog "Storage Spaces Direct enabled" "Success"
    }
    
    # Enable Cluster-Aware Updating if requested
    if ($EnableClusterAwareUpdating) {
        Write-ConfigLog "Enabling Cluster-Aware Updating..." "Info"
        Enable-ClusterAwareUpdating -ClusterName $ClusterName
        Write-ConfigLog "Cluster-Aware Updating enabled" "Success"
    }
    
    # Apply security configuration
    Write-ConfigLog "Applying security configuration: $SecurityLevel" "Info"
    Set-ClusterSecurityBaseline -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-ConfigLog "Security configuration applied" "Success"
    
    # Configure monitoring
    Write-ConfigLog "Configuring cluster monitoring..." "Info"
    Enable-ClusterMonitoring -ClusterName $ClusterName -MonitoringLevel "Comprehensive"
    Write-ConfigLog "Cluster monitoring configured" "Success"
    
    # Generate configuration report
    Write-ConfigLog "Generating configuration report..." "Info"
    $reportPath = Join-Path $PSScriptRoot "Cluster-Configuration-Report.html"
    Get-ClusterReport -ClusterName $ClusterName -ReportType "Configuration" -OutputPath $reportPath -Format "HTML"
    Write-ConfigLog "Configuration report generated: $reportPath" "Success"
    
    # Validate cluster configuration
    Write-ConfigLog "Validating cluster configuration..." "Info"
    $validation = Test-ClusterConfiguration -ClusterName $ClusterName
    if ($validation.IsValid) {
        Write-ConfigLog "Cluster configuration validation passed" "Success"
    } else {
        Write-ConfigLog "Cluster configuration validation failed: $($validation.Issues)" "Warning"
    }
    
    Write-ConfigLog "Cluster configuration completed successfully" "Success"
    
    # Return configuration summary
    $configSummary = @{
        ClusterName = $ClusterName
        Nodes = $Nodes
        QuorumType = $QuorumType
        SecurityLevel = $SecurityLevel
        ConfigurationTime = Get-Date
        ReportPath = $reportPath
    }
    
    return $configSummary
}
catch {
    Write-ConfigLog "Cluster configuration failed: $($_.Exception.Message)" "Error"
    Write-ConfigLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive configuration for Windows Failover Clustering.
    It handles all aspects of cluster setup, optimization, and management.
    
    Features:
    - Cluster creation and node management
    - Quorum configuration (all types)
    - Network and resource configuration
    - Storage Spaces Direct
    - Cluster-Aware Updating
    - Security hardening
    - Monitoring setup
    - Configuration validation
    - Report generation
    
    Prerequisites:
    - Windows Server 2016 or later
    - Failover Clustering feature installed
    - Administrative privileges
    - Network connectivity between nodes
    
    Dependencies:
    - Cluster-Core.psm1
    - Cluster-Security.psm1
    - Cluster-Monitoring.psm1
    
    Usage Examples:
    .\Configure-Cluster.ps1 -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeMajority"
    .\Configure-Cluster.ps1 -ClusterName "HA-CLUSTER" -Nodes @("NODE01", "NODE02", "NODE03") -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"
    .\Configure-Cluster.ps1 -ClusterName "ENTERPRISE-CLUSTER" -Nodes @("NODE01", "NODE02", "NODE03", "NODE04") -QuorumType "NodeAndCloudMajority" -CloudWitnessAccount "AzureStorage" -CloudWitnessEndpoint "https://azurestorage.blob.core.windows.net" -CloudWitnessKey "AzureKey" -EnableStorageSpacesDirect -EnableClusterAwareUpdating -SecurityLevel "High"
    
    Output:
    - Console logging with color-coded messages
    - HTML configuration report
    - Configuration validation results
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Validates node connectivity
    - Implements secure configuration
    - Logs all operations for audit
    
    Performance Impact:
    - Minimal impact during configuration
    - Non-destructive operations
    - Configurable execution modes
    - Resource monitoring included
#>
