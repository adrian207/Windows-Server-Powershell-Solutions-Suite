#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Cluster-Core Module for Windows Failover Clustering

.DESCRIPTION
    Core functions for Windows Failover Clustering operations including:
    - Cluster creation and management
    - Node management
    - Resource management
    - Quorum configuration
    - Basic operations and status checks

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Failover Clustering feature
#>

# Module variables
# $ModuleName = "Cluster-Core"
# $ModuleVersion = "1.0.0"

# Import required modules
Import-Module FailoverClusters -ErrorAction Stop

function New-FailoverCluster {
    <#
    .SYNOPSIS
        Create a new failover cluster

    .DESCRIPTION
        Creates a new failover cluster with specified nodes and configuration

    .PARAMETER ClusterName
        Name of the cluster to create

    .PARAMETER Nodes
        Array of node names to include in the cluster

    .PARAMETER QuorumType
        Type of quorum to use (NodeMajority, NodeAndDiskMajority, NodeAndFileShareMajority, NodeAndCloudMajority)

    .PARAMETER WitnessShare
        File share path for quorum witness (if using NodeAndFileShareMajority)

    .PARAMETER CloudWitnessAccountName
        Azure storage account name for cloud witness (if using NodeAndCloudMajority)

    .PARAMETER CloudWitnessEndpoint
        Azure storage endpoint for cloud witness

    .PARAMETER CloudWitnessKey
        Azure storage key for cloud witness

    .PARAMETER StaticIPAddress
        Static IP address for the cluster

    .PARAMETER ManagementPoint
        Management point for the cluster

    .PARAMETER Force
        Force cluster creation without confirmation

    .EXAMPLE
        New-FailoverCluster -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeMajority"

    .EXAMPLE
        New-FailoverCluster -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"
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
        [switch]$Force
    )

    try {
        Write-Host "Creating failover cluster: $ClusterName" -ForegroundColor Green

        # Validate nodes
        foreach ($node in $Nodes) {
            if (!(Test-Connection -ComputerName $node -Count 1 -Quiet)) {
                throw "Node $node is not reachable"
            }
        }

        # Create cluster
        $clusterParams = @{
            Name = $ClusterName
            Node = $Nodes
            StaticAddress = $StaticIPAddress
            ManagementPoint = $ManagementPoint
            Force = $Force
        }

        $cluster = New-Cluster @clusterParams

        if ($cluster) {
            Write-Host "Cluster $ClusterName created successfully" -ForegroundColor Green

            # Configure quorum
            if ($QuorumType -ne "NodeMajority") {
                Set-ClusterQuorum -Cluster $ClusterName -QuorumType $QuorumType -WitnessShare $WitnessShare -CloudWitnessAccountName $CloudWitnessAccountName -CloudWitnessEndpoint $CloudWitnessEndpoint -CloudWitnessKey $CloudWitnessKey
                Write-Host "Quorum configured as $QuorumType" -ForegroundColor Green
            }

            return $cluster
        } else {
            throw "Failed to create cluster $ClusterName"
        }
    }
    catch {
        Write-Error "Failed to create cluster: $($_.Exception.Message)"
        throw
    }
}

function Add-ClusterNode {
    <#
    .SYNOPSIS
        Add a node to an existing failover cluster

    .DESCRIPTION
        Adds a new node to an existing failover cluster

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER NodeName
        Name of the node to add

    .PARAMETER Force
        Force node addition without confirmation

    .EXAMPLE
        Add-ClusterNode -ClusterName "PROD-CLUSTER" -NodeName "NODE03"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [string]$NodeName,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        Write-Host "Adding node $NodeName to cluster $ClusterName" -ForegroundColor Green

        # Validate node
        if (!(Test-Connection -ComputerName $NodeName -Count 1 -Quiet)) {
            throw "Node $NodeName is not reachable"
        }

        # Add node to cluster
        Add-ClusterNode -Cluster $ClusterName -Name $NodeName -Force:$Force

        Write-Host "Node $NodeName added to cluster $ClusterName successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to add node: $($_.Exception.Message)"
        throw
    }
}

function Remove-ClusterNode {
    <#
    .SYNOPSIS
        Remove a node from a failover cluster

    .DESCRIPTION
        Removes a node from a failover cluster

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER NodeName
        Name of the node to remove

    .PARAMETER Force
        Force node removal without confirmation

    .EXAMPLE
        Remove-ClusterNode -ClusterName "PROD-CLUSTER" -NodeName "NODE03"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [string]$NodeName,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        Write-Host "Removing node $NodeName from cluster $ClusterName" -ForegroundColor Yellow

        # Remove node from cluster
        Remove-ClusterNode -Cluster $ClusterName -Name $NodeName -Force:$Force

        Write-Host "Node $NodeName removed from cluster $ClusterName successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to remove node: $($_.Exception.Message)"
        throw
    }
}

function Get-ClusterStatus {
    <#
    .SYNOPSIS
        Get failover cluster status and health information

    .DESCRIPTION
        Gets comprehensive status and health information for a failover cluster

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER IncludeDetails
        Include detailed status information

    .EXAMPLE
        Get-ClusterStatus -ClusterName "PROD-CLUSTER"

    .EXAMPLE
        Get-ClusterStatus -ClusterName "PROD-CLUSTER" -IncludeDetails
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails
    )

    try {
        $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
        
        $status = @{
            ClusterName = $cluster.Name
            State = $cluster.State
            QuorumType = $cluster.QuorumType
            QuorumState = $cluster.QuorumState
            Nodes = @()
            Resources = @()
            Networks = @()
            Issues = @()
        }

        # Get cluster nodes
        $nodes = Get-ClusterNode -Cluster $ClusterName
        foreach ($node in $nodes) {
            $nodeInfo = @{
                Name = $node.Name
                State = $node.State
                IsVote = $node.IsVote
                IsUp = $node.IsUp
            }
            $status.Nodes += $nodeInfo
        }

        # Get cluster resources
        $resources = Get-ClusterResource -Cluster $ClusterName
        foreach ($resource in $resources) {
            $resourceInfo = @{
                Name = $resource.Name
                State = $resource.State
                OwnerNode = $resource.OwnerNode
                ResourceType = $resource.ResourceType
            }
            $status.Resources += $resourceInfo
        }

        # Get cluster networks
        $networks = Get-ClusterNetwork -Cluster $ClusterName
        foreach ($network in $networks) {
            $networkInfo = @{
                Name = $network.Name
                State = $network.State
                Role = $network.Role
                Address = $network.Address
            }
            $status.Networks += $networkInfo
        }

        # Check for issues
        if ($cluster.State -ne "Up") {
            $status.Issues += "Cluster is not in Up state"
        }

        $downNodes = $status.Nodes | Where-Object { $_.State -ne "Up" }
        if ($downNodes) {
            $status.Issues += "Nodes are down: $($downNodes.Name -join ', ')"
        }

        $failedResources = $status.Resources | Where-Object { $_.State -ne "Online" }
        if ($failedResources) {
            $status.Issues += "Resources are not online: $($failedResources.Name -join ', ')"
        }

        if ($IncludeDetails) {
            $status.DetailedInfo = @{
                Cluster = $cluster
                Nodes = $nodes
                Resources = $resources
                Networks = $networks
            }
        }

        return $status
    }
    catch {
        Write-Error "Failed to get cluster status: $($_.Exception.Message)"
        throw
    }
}

function Set-ClusterQuorum {
    <#
    .SYNOPSIS
        Configure cluster quorum settings

    .DESCRIPTION
        Configures quorum settings for a failover cluster

    .PARAMETER ClusterName
        Name of the cluster

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

    .PARAMETER WitnessDisk
        Disk to use as quorum witness

    .EXAMPLE
        Set-ClusterQuorum -ClusterName "PROD-CLUSTER" -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("NodeMajority", "NodeAndDiskMajority", "NodeAndFileShareMajority", "NodeAndCloudMajority")]
        [string]$QuorumType,

        [Parameter(Mandatory = $false)]
        [string]$WitnessShare,

        [Parameter(Mandatory = $false)]
        [string]$CloudWitnessAccountName,

        [Parameter(Mandatory = $false)]
        [string]$CloudWitnessEndpoint,

        [Parameter(Mandatory = $false)]
        [string]$CloudWitnessKey,

        [Parameter(Mandatory = $false)]
        [string]$WitnessDisk
    )

    try {
        Write-Host "Configuring quorum for cluster $ClusterName as $QuorumType" -ForegroundColor Green

        $quorumParams = @{
            Cluster = $ClusterName
            QuorumType = $QuorumType
        }

        switch ($QuorumType) {
            "NodeAndFileShareMajority" {
                if ($WitnessShare) {
                    $quorumParams.WitnessShare = $WitnessShare
                } else {
                    throw "WitnessShare is required for NodeAndFileShareMajority quorum type"
                }
            }
            "NodeAndCloudMajority" {
                if ($CloudWitnessAccountName -and $CloudWitnessEndpoint -and $CloudWitnessKey) {
                    $quorumParams.CloudWitnessAccountName = $CloudWitnessAccountName
                    $quorumParams.CloudWitnessEndpoint = $CloudWitnessEndpoint
                    $quorumParams.CloudWitnessKey = $CloudWitnessKey
                } else {
                    throw "Cloud witness parameters are required for NodeAndCloudMajority quorum type"
                }
            }
            "NodeAndDiskMajority" {
                if ($WitnessDisk) {
                    $quorumParams.WitnessDisk = $WitnessDisk
                } else {
                    throw "WitnessDisk is required for NodeAndDiskMajority quorum type"
                }
            }
        }

        Set-ClusterQuorum @quorumParams

        Write-Host "Quorum configured successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to configure quorum: $($_.Exception.Message)"
        throw
    }
}

function New-ClusterResource {
    <#
    .SYNOPSIS
        Create a new clustered resource

    .DESCRIPTION
        Creates a new clustered resource in a failover cluster

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER ResourceName
        Name of the resource to create

    .PARAMETER ResourceType
        Type of resource to create

    .PARAMETER Group
        Resource group to add the resource to

    .PARAMETER Dependencies
        Array of resource dependencies

    .PARAMETER Parameters
        Hashtable of resource parameters

    .EXAMPLE
        New-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "FileShare" -ResourceType "File Server" -Group "FileServerGroup"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceType,

        [Parameter(Mandatory = $false)]
        [string]$Group,

        [Parameter(Mandatory = $false)]
        [string[]]$Dependencies,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters
    )

    try {
        Write-Host "Creating clustered resource: $ResourceName" -ForegroundColor Green

        $resourceParams = @{
            Cluster = $ClusterName
            Name = $ResourceName
            ResourceType = $ResourceType
            Group = $Group
        }

        if ($Dependencies) {
            $resourceParams.Dependencies = $Dependencies
        }

        $resource = New-ClusterResource @resourceParams

        if ($Parameters) {
            foreach ($param in $Parameters.GetEnumerator()) {
                Set-ClusterParameter -Cluster $ClusterName -InputObject $resource -Name $param.Key -Value $param.Value
            }
        }

        Write-Host "Clustered resource $ResourceName created successfully" -ForegroundColor Green
        return $resource
    }
    catch {
        Write-Error "Failed to create clustered resource: $($_.Exception.Message)"
        throw
    }
}

function Start-ClusterResource {
    <#
    .SYNOPSIS
        Start a clustered resource

    .DESCRIPTION
        Starts a clustered resource

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER ResourceName
        Name of the resource to start

    .PARAMETER Node
        Specific node to start the resource on

    .EXAMPLE
        Start-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "FileShare"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceName,

        [Parameter(Mandatory = $false)]
        [string]$Node
    )

    try {
        Write-Host "Starting clustered resource: $ResourceName" -ForegroundColor Green

        $resource = Get-ClusterResource -Cluster $ClusterName -Name $ResourceName

        if ($Node) {
            Move-ClusterResource -Cluster $ClusterName -InputObject $resource -Node $Node
        }

        Start-ClusterResource -Cluster $ClusterName -InputObject $resource

        Write-Host "Clustered resource $ResourceName started successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to start clustered resource: $($_.Exception.Message)"
        throw
    }
}

function Stop-ClusterResource {
    <#
    .SYNOPSIS
        Stop a clustered resource

    .DESCRIPTION
        Stops a clustered resource

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER ResourceName
        Name of the resource to stop

    .EXAMPLE
        Stop-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "FileShare"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceName
    )

    try {
        Write-Host "Stopping clustered resource: $ResourceName" -ForegroundColor Yellow

        $resource = Get-ClusterResource -Cluster $ClusterName -Name $ResourceName
        Stop-ClusterResource -Cluster $ClusterName -InputObject $resource

        Write-Host "Clustered resource $ResourceName stopped successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to stop clustered resource: $($_.Exception.Message)"
        throw
    }
}

function Move-ClusterResource {
    <#
    .SYNOPSIS
        Move a clustered resource to another node

    .DESCRIPTION
        Moves a clustered resource to another node

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER ResourceName
        Name of the resource to move

    .PARAMETER Node
        Target node to move the resource to

    .PARAMETER Force
        Force the move operation

    .EXAMPLE
        Move-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "FileShare" -Node "NODE02"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [string]$ResourceName,

        [Parameter(Mandatory = $true)]
        [string]$Node,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        Write-Host "Moving clustered resource $ResourceName to node $Node" -ForegroundColor Green

        $resource = Get-ClusterResource -Cluster $ClusterName -Name $ResourceName
        Move-ClusterResource -Cluster $ClusterName -InputObject $resource -Node $Node -Force:$Force

        Write-Host "Clustered resource $ResourceName moved to node $Node successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to move clustered resource: $($_.Exception.Message)"
        throw
    }
}

function Test-ClusterConnectivity {
    <#
    .SYNOPSIS
        Test cluster connectivity

    .DESCRIPTION
        Tests connectivity between cluster nodes

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER TestType
        Type of connectivity test to perform

    .EXAMPLE
        Test-ClusterConnectivity -ClusterName "PROD-CLUSTER"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Basic", "Comprehensive")]
        [string]$TestType = "Basic"
    )

    try {
        Write-Host "Testing cluster connectivity for $ClusterName" -ForegroundColor Green

        $cluster = Get-Cluster -Name $ClusterName
        $nodes = Get-ClusterNode -Cluster $ClusterName

        $testResults = @{
            ClusterName = $ClusterName
            TestType = $TestType
            Nodes = @()
            OverallResult = "Pass"
            Issues = @()
        }

        foreach ($node in $nodes) {
            $nodeTest = @{
                Name = $node.Name
                PingTest = $false
                ClusterServiceTest = $false
                NetworkTest = $false
            }

            # Test ping connectivity
            try {
                $pingResult = Test-Connection -ComputerName $node.Name -Count 1 -Quiet
                $nodeTest.PingTest = $pingResult
            }
            catch {
                $nodeTest.PingTest = $false
                $testResults.Issues += "Ping test failed for node $($node.Name)"
            }

            # Test cluster service
            try {
                $service = Get-Service -ComputerName $node.Name -Name "ClusSvc" -ErrorAction Stop
                $nodeTest.ClusterServiceTest = ($service.Status -eq "Running")
            }
            catch {
                $nodeTest.ClusterServiceTest = $false
                $testResults.Issues += "Cluster service test failed for node $($node.Name)"
            }

            # Test network connectivity
            try {
                $networks = Get-ClusterNetwork -Cluster $ClusterName -Node $node.Name
                $nodeTest.NetworkTest = ($networks.Count -gt 0)
            }
            catch {
                $nodeTest.NetworkTest = $false
                $testResults.Issues += "Network test failed for node $($node.Name)"
            }

            $testResults.Nodes += $nodeTest
        }

        if ($testResults.Issues.Count -gt 0) {
            $testResults.OverallResult = "Fail"
        }

        return $testResults
    }
    catch {
        Write-Error "Failed to test cluster connectivity: $($_.Exception.Message)"
        throw
    }
}

function Get-ClusterValidation {
    <#
    .SYNOPSIS
        Run cluster validation

    .DESCRIPTION
        Runs cluster validation to check configuration

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER ValidationType
        Type of validation to run

    .EXAMPLE
        Get-ClusterValidation -ClusterName "PROD-CLUSTER"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Basic", "Comprehensive")]
        [string]$ValidationType = "Basic"
    )

    try {
        Write-Host "Running cluster validation for $ClusterName" -ForegroundColor Green

        $validationParams = @{
            Cluster = $ClusterName
        }

        switch ($ValidationType) {
            "Basic" {
                $validationParams.Tests = @("Storage", "System Configuration", "Network")
            }
            "Comprehensive" {
                $validationParams.Tests = @("Storage", "System Configuration", "Network", "Hyper-V", "Inventory")
            }
            "All" {
                # Run all tests
            }
        }

        $validationResult = Test-Cluster @validationParams

        return $validationResult
    }
    catch {
        Write-Error "Failed to run cluster validation: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'New-FailoverCluster',
    'Add-ClusterNode',
    'Remove-ClusterNode',
    'Get-ClusterStatus',
    'Set-ClusterQuorum',
    'New-ClusterResource',
    'Start-ClusterResource',
    'Stop-ClusterResource',
    'Move-ClusterResource',
    'Test-ClusterConnectivity',
    'Get-ClusterValidation'
)
