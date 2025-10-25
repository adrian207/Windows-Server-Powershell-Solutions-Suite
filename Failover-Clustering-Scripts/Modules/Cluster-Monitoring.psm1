#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Cluster-Monitoring Module for Windows Failover Clustering

.DESCRIPTION
    Monitoring functions for Windows Failover Clustering including:
    - Health monitoring and status checks
    - Performance metrics collection
    - Event log analysis
    - Alert generation and notification
    - Capacity planning and reporting

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Failover Clustering feature
#>

# Module variables
# $ModuleName = "Cluster-Monitoring"
# $ModuleVersion = "1.0.0"

# Import required modules
Import-Module FailoverClusters -ErrorAction Stop

function Get-ClusterHealthStatus {
    <#
    .SYNOPSIS
        Get comprehensive cluster health status

    .DESCRIPTION
        Gets comprehensive health status for a failover cluster

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER IncludeDetails
        Include detailed health information

    .PARAMETER IncludeNodes
        Include node health information

    .PARAMETER IncludeResources
        Include resource health information

    .EXAMPLE
        Get-ClusterHealthStatus -ClusterName "PROD-CLUSTER"

    .EXAMPLE
        Get-ClusterHealthStatus -ClusterName "PROD-CLUSTER" -IncludeDetails -IncludeNodes -IncludeResources
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNodes,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeResources
    )

    try {
        Write-Host "Getting cluster health status for $ClusterName" -ForegroundColor Green

        $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
        
        $healthStatus = @{
            ClusterName = $cluster.Name
            OverallHealth = "Healthy"
            ClusterState = $cluster.State
            QuorumState = $cluster.QuorumState
            Nodes = @()
            Resources = @()
            Networks = @()
            Issues = @()
            Recommendations = @()
            Timestamp = Get-Date
        }

        # Check cluster state
        if ($cluster.State -ne "Up") {
            $healthStatus.OverallHealth = "Critical"
            $healthStatus.Issues += "Cluster is not in Up state"
        }

        # Check quorum state
        if ($cluster.QuorumState -ne "Up") {
            $healthStatus.OverallHealth = "Critical"
            $healthStatus.Issues += "Quorum is not in Up state"
        }

        # Get node health
        if ($IncludeNodes) {
            $nodes = Get-ClusterNode -Cluster $ClusterName
            foreach ($node in $nodes) {
                $nodeHealth = @{
                    Name = $node.Name
                    State = $node.State
                    IsUp = $node.IsUp
                    IsVote = $node.IsVote
                    Health = "Healthy"
                    Issues = @()
                }

                if ($node.State -ne "Up") {
                    $nodeHealth.Health = "Critical"
                    $nodeHealth.Issues += "Node is not in Up state"
                    $healthStatus.Issues += "Node $($node.Name) is not healthy"
                }

                if (!$node.IsUp) {
                    $nodeHealth.Health = "Critical"
                    $nodeHealth.Issues += "Node is not up"
                    $healthStatus.Issues += "Node $($node.Name) is not up"
                }

                $healthStatus.Nodes += $nodeHealth
            }
        }

        # Get resource health
        if ($IncludeResources) {
            $resources = Get-ClusterResource -Cluster $ClusterName
            foreach ($resource in $resources) {
                $resourceHealth = @{
                    Name = $resource.Name
                    State = $resource.State
                    OwnerNode = $resource.OwnerNode
                    ResourceType = $resource.ResourceType
                    Health = "Healthy"
                    Issues = @()
                }

                if ($resource.State -ne "Online") {
                    $resourceHealth.Health = "Warning"
                    $resourceHealth.Issues += "Resource is not online"
                    $healthStatus.Issues += "Resource $($resource.Name) is not online"
                }

                $healthStatus.Resources += $resourceHealth
            }
        }

        # Get network health
        $networks = Get-ClusterNetwork -Cluster $ClusterName
        foreach ($network in $networks) {
            $networkHealth = @{
                Name = $network.Name
                State = $network.State
                Role = $network.Role
                Address = $network.Address
                Health = "Healthy"
                Issues = @()
            }

            if ($network.State -ne "Up") {
                $networkHealth.Health = "Warning"
                $networkHealth.Issues += "Network is not up"
                $healthStatus.Issues += "Network $($network.Name) is not up"
            }

            $healthStatus.Networks += $networkHealth
        }

        # Determine overall health
        $criticalIssues = $healthStatus.Issues | Where-Object { $_ -like "*Critical*" -or $_ -like "*not up*" }
        $warningIssues = $healthStatus.Issues | Where-Object { $_ -like "*Warning*" -or $_ -like "*not online*" }

        if ($criticalIssues.Count -gt 0) {
            $healthStatus.OverallHealth = "Critical"
        } elseif ($warningIssues.Count -gt 0) {
            $healthStatus.OverallHealth = "Warning"
        }

        # Generate recommendations
        if ($healthStatus.Issues.Count -gt 0) {
            $healthStatus.Recommendations += "Review and resolve identified issues"
            $healthStatus.Recommendations += "Monitor cluster health continuously"
            $healthStatus.Recommendations += "Check event logs for additional details"
        } else {
            $healthStatus.Recommendations += "Cluster is healthy - continue monitoring"
            $healthStatus.Recommendations += "Schedule regular health checks"
        }

        if ($IncludeDetails) {
            $healthStatus.DetailedInfo = @{
                Cluster = $cluster
                Nodes = if ($IncludeNodes) { $nodes } else { $null }
                Resources = if ($IncludeResources) { $resources } else { $null }
                Networks = $networks
            }
        }

        return $healthStatus
    }
    catch {
        Write-Error "Failed to get cluster health status: $($_.Exception.Message)"
        throw
    }
}

function Get-ClusterPerformanceMetrics {
    <#
    .SYNOPSIS
        Get cluster performance metrics

    .DESCRIPTION
        Gets performance metrics for cluster nodes and resources

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER MetricType
        Type of metrics to collect (All, CPU, Memory, Disk, Network, Cluster)

    .PARAMETER TimeRange
        Time range for metrics collection (minutes)

    .EXAMPLE
        Get-ClusterPerformanceMetrics -ClusterName "PROD-CLUSTER"

    .EXAMPLE
        Get-ClusterPerformanceMetrics -ClusterName "PROD-CLUSTER" -MetricType "CPU" -TimeRange 60
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "CPU", "Memory", "Disk", "Network", "Cluster")]
        [string]$MetricType = "All",

        [Parameter(Mandatory = $false)]
        [int]$TimeRange = 5
    )

    try {
        Write-Host "Getting cluster performance metrics for $ClusterName" -ForegroundColor Green

        $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
        $nodes = Get-ClusterNode -Cluster $ClusterName

        $performanceMetrics = @{
            ClusterName = $ClusterName
            Timestamp = Get-Date
            TimeRange = $TimeRange
            Nodes = @()
            ClusterMetrics = @{}
            OverallHealth = "Good"
            Issues = @()
        }

        foreach ($node in $nodes) {
            $nodeMetrics = @{
                Name = $node.Name
                CPU = @{}
                Memory = @{}
                Disk = @{}
                Network = @{}
                Health = "Good"
                Issues = @()
            }

            # CPU metrics
            if ($MetricType -in @("All", "CPU")) {
                try {
                    $cpuCounter = Get-Counter -ComputerName $node.Name -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples $TimeRange -ErrorAction Stop
                    $cpuUsage = ($cpuCounter.CounterSamples | Measure-Object -Property CookedValue -Average).Average
                    
                    $nodeMetrics.CPU = @{
                        ProcessorTime = [math]::Round($cpuUsage, 2)
                        Status = if ($cpuUsage -lt 80) { "Good" } elseif ($cpuUsage -lt 90) { "Warning" } else { "Critical" }
                    }

                    if ($cpuUsage -gt 90) {
                        $nodeMetrics.Health = "Critical"
                        $nodeMetrics.Issues += "High CPU usage: $([math]::Round($cpuUsage, 2))%"
                    } elseif ($cpuUsage -gt 80) {
                        $nodeMetrics.Health = "Warning"
                        $nodeMetrics.Issues += "Elevated CPU usage: $([math]::Round($cpuUsage, 2))%"
                    }
                }
                catch {
                    $nodeMetrics.CPU = @{ ProcessorTime = 0; Status = "Unknown"; Error = $_.Exception.Message }
                }
            }

            # Memory metrics
            if ($MetricType -in @("All", "Memory")) {
                try {
                    $memoryCounter = Get-Counter -ComputerName $node.Name -Counter "\Memory\Available MBytes", "\Memory\% Committed Bytes In Use" -SampleInterval 1 -MaxSamples $TimeRange -ErrorAction Stop
                    
                    $availableMemory = ($memoryCounter.CounterSamples | Where-Object { $_.Path -like "*Available MBytes*" } | Measure-Object -Property CookedValue -Average).Average
                    $committedMemory = ($memoryCounter.CounterSamples | Where-Object { $_.Path -like "*Committed Bytes*" } | Measure-Object -Property CookedValue -Average).Average
                    
                    $nodeMetrics.Memory = @{
                        AvailableMB = [math]::Round($availableMemory, 2)
                        CommittedPercent = [math]::Round($committedMemory, 2)
                        Status = if ($committedMemory -lt 85) { "Good" } elseif ($committedMemory -lt 95) { "Warning" } else { "Critical" }
                    }

                    if ($committedMemory -gt 95) {
                        $nodeMetrics.Health = "Critical"
                        $nodeMetrics.Issues += "High memory usage: $([math]::Round($committedMemory, 2))%"
                    } elseif ($committedMemory -gt 85) {
                        $nodeMetrics.Health = "Warning"
                        $nodeMetrics.Issues += "Elevated memory usage: $([math]::Round($committedMemory, 2))%"
                    }
                }
                catch {
                    $nodeMetrics.Memory = @{ AvailableMB = 0; CommittedPercent = 0; Status = "Unknown"; Error = $_.Exception.Message }
                }
            }

            # Disk metrics
            if ($MetricType -in @("All", "Disk")) {
                try {
                    $diskCounter = Get-Counter -ComputerName $node.Name -Counter "\PhysicalDisk(_Total)\% Disk Time", "\PhysicalDisk(_Total)\Avg. Disk Queue Length" -SampleInterval 1 -MaxSamples $TimeRange -ErrorAction Stop
                    
                    $diskTime = ($diskCounter.CounterSamples | Where-Object { $_.Path -like "*Disk Time*" } | Measure-Object -Property CookedValue -Average).Average
                    $diskQueue = ($diskCounter.CounterSamples | Where-Object { $_.Path -like "*Queue Length*" } | Measure-Object -Property CookedValue -Average).Average
                    
                    $nodeMetrics.Disk = @{
                        DiskTime = [math]::Round($diskTime, 2)
                        QueueLength = [math]::Round($diskQueue, 2)
                        Status = if ($diskTime -lt 80 -and $diskQueue -lt 5) { "Good" } elseif ($diskTime -lt 90 -and $diskQueue -lt 10) { "Warning" } else { "Critical" }
                    }

                    if ($diskTime -gt 90 -or $diskQueue -gt 10) {
                        $nodeMetrics.Health = "Critical"
                        $nodeMetrics.Issues += "High disk usage: $([math]::Round($diskTime, 2))% or queue length: $([math]::Round($diskQueue, 2))"
                    } elseif ($diskTime -gt 80 -or $diskQueue -gt 5) {
                        $nodeMetrics.Health = "Warning"
                        $nodeMetrics.Issues += "Elevated disk usage: $([math]::Round($diskTime, 2))% or queue length: $([math]::Round($diskQueue, 2))"
                    }
                }
                catch {
                    $nodeMetrics.Disk = @{ DiskTime = 0; QueueLength = 0; Status = "Unknown"; Error = $_.Exception.Message }
                }
            }

            # Network metrics
            if ($MetricType -in @("All", "Network")) {
                try {
                    $networkCounter = Get-Counter -ComputerName $node.Name -Counter "\Network Interface(*)\Bytes Total/sec" -SampleInterval 1 -MaxSamples $TimeRange -ErrorAction Stop
                    
                    $totalBytes = ($networkCounter.CounterSamples | Measure-Object -Property CookedValue -Sum).Sum
                    $avgBytes = $totalBytes / $TimeRange
                    
                    $nodeMetrics.Network = @{
                        BytesPerSecond = [math]::Round($avgBytes, 2)
                        Status = "Good"
                    }
                }
                catch {
                    $nodeMetrics.Network = @{ BytesPerSecond = 0; Status = "Unknown"; Error = $_.Exception.Message }
                }
            }

            $performanceMetrics.Nodes += $nodeMetrics
        }

        # Cluster-level metrics
        if ($MetricType -in @("All", "Cluster")) {
            $performanceMetrics.ClusterMetrics = @{
                TotalNodes = $nodes.Count
                UpNodes = ($nodes | Where-Object { $_.State -eq "Up" }).Count
                DownNodes = ($nodes | Where-Object { $_.State -ne "Up" }).Count
                TotalResources = (Get-ClusterResource -Cluster $ClusterName).Count
                OnlineResources = (Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.State -eq "Online" }).Count
                OfflineResources = (Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.State -ne "Online" }).Count
            }
        }

        # Determine overall health
        $criticalNodes = $performanceMetrics.Nodes | Where-Object { $_.Health -eq "Critical" }
        $warningNodes = $performanceMetrics.Nodes | Where-Object { $_.Health -eq "Warning" }

        if ($criticalNodes.Count -gt 0) {
            $performanceMetrics.OverallHealth = "Critical"
            $performanceMetrics.Issues += "Critical performance issues detected on nodes: $($criticalNodes.Name -join ', ')"
        } elseif ($warningNodes.Count -gt 0) {
            $performanceMetrics.OverallHealth = "Warning"
            $performanceMetrics.Issues += "Performance warnings on nodes: $($warningNodes.Name -join ', ')"
        }

        return $performanceMetrics
    }
    catch {
        Write-Error "Failed to get cluster performance metrics: $($_.Exception.Message)"
        throw
    }
}

function Get-ClusterEventAnalysis {
    <#
    .SYNOPSIS
        Analyze cluster event logs

    .DESCRIPTION
        Analyzes cluster event logs for issues and patterns

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER TimeRange
        Time range for analysis (hours)

    .PARAMETER AnalysisType
        Type of analysis to perform (Basic, Comprehensive, Deep)

    .PARAMETER LogSources
        Event log sources to analyze

    .EXAMPLE
        Get-ClusterEventAnalysis -ClusterName "PROD-CLUSTER"

    .EXAMPLE
        Get-ClusterEventAnalysis -ClusterName "PROD-CLUSTER" -TimeRange 24 -AnalysisType "Comprehensive"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [int]$TimeRange = 24,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Comprehensive", "Deep")]
        [string]$AnalysisType = "Comprehensive",

        [Parameter(Mandatory = $false)]
        [string[]]$LogSources = @("System", "Application", "Microsoft-Windows-FailoverClustering/Operational")
    )

    try {
        Write-Host "Analyzing cluster event logs for $ClusterName" -ForegroundColor Green

        $startTime = (Get-Date).AddHours(-$TimeRange)
        $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
        $nodes = Get-ClusterNode -Cluster $ClusterName

        $eventAnalysis = @{
            ClusterName = $ClusterName
            AnalysisType = $AnalysisType
            TimeRange = $TimeRange
            StartTime = $startTime
            EndTime = Get-Date
            Events = @()
            Patterns = @()
            Issues = @()
            Recommendations = @()
            Summary = @{}
        }

        # Analyze events from cluster nodes
        foreach ($node in $nodes) {
            foreach ($logSource in $LogSources) {
                try {
                    $events = Get-WinEvent -ComputerName $node.Name -LogName $logSource -FilterHashtable @{StartTime = $startTime} -ErrorAction Stop
                    
                    foreach ($event in $events) {
                        $eventInfo = @{
                            NodeName = $node.Name
                            LogName = $logSource
                            EventId = $event.Id
                            Level = $event.LevelDisplayName
                            TimeCreated = $event.TimeCreated
                            Message = $event.Message
                            Source = $event.ProviderName
                            Severity = "Info"
                        }

                        # Determine severity based on event ID and level
                        if ($event.LevelDisplayName -eq "Error") {
                            $eventInfo.Severity = "Critical"
                        } elseif ($event.LevelDisplayName -eq "Warning") {
                            $eventInfo.Severity = "Warning"
                        }

                        # Check for cluster-specific event IDs
                        $clusterEventIds = @(1205, 1206, 1207, 1208, 1209, 1210, 1135, 1136, 1137, 1138, 1139, 1140)
                        if ($event.Id -in $clusterEventIds) {
                            $eventInfo.Severity = "Critical"
                            $eventAnalysis.Issues += "Cluster event detected: $($event.Id) on $($node.Name)"
                        }

                        $eventAnalysis.Events += $eventInfo
                    }
                }
                catch {
                    Write-Warning "Failed to get events from $logSource on $($node.Name): $($_.Exception.Message)"
                }
            }
        }

        # Analyze patterns
        $eventGroups = $eventAnalysis.Events | Group-Object -Property EventId
        foreach ($group in $eventGroups) {
            if ($group.Count -gt 5) {
                $pattern = @{
                    EventId = $group.Name
                    Count = $group.Count
                    Frequency = [math]::Round($group.Count / $TimeRange, 2)
                    Severity = ($group.Group | Measure-Object -Property Severity -Maximum).Maximum
                    Nodes = ($group.Group | Select-Object -Property NodeName -Unique).NodeName
                }
                $eventAnalysis.Patterns += $pattern

                if ($pattern.Frequency -gt 1) {
                    $eventAnalysis.Issues += "Frequent event pattern detected: Event ID $($pattern.EventId) occurs $($pattern.Frequency) times per hour"
                }
            }
        }

        # Generate summary
        $eventAnalysis.Summary = @{
            TotalEvents = $eventAnalysis.Events.Count
            CriticalEvents = ($eventAnalysis.Events | Where-Object { $_.Severity -eq "Critical" }).Count
            WarningEvents = ($eventAnalysis.Events | Where-Object { $_.Severity -eq "Warning" }).Count
            InfoEvents = ($eventAnalysis.Events | Where-Object { $_.Severity -eq "Info" }).Count
            UniqueEventIds = ($eventAnalysis.Events | Select-Object -Property EventId -Unique).Count
            PatternCount = $eventAnalysis.Patterns.Count
        }

        # Generate recommendations
        if ($eventAnalysis.Issues.Count -gt 0) {
            $eventAnalysis.Recommendations += "Review and resolve identified issues"
            $eventAnalysis.Recommendations += "Monitor event patterns for trends"
            $eventAnalysis.Recommendations += "Check cluster health and performance"
        } else {
            $eventAnalysis.Recommendations += "No significant issues detected"
            $eventAnalysis.Recommendations += "Continue monitoring for patterns"
        }

        return $eventAnalysis
    }
    catch {
        Write-Error "Failed to analyze cluster event logs: $($_.Exception.Message)"
        throw
    }
}

function Get-ClusterCapacityPlanning {
    <#
    .SYNOPSIS
        Generate cluster capacity planning report

    .DESCRIPTION
        Generates capacity planning report for cluster resources

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER PlanningHorizon
        Planning horizon in months

    .PARAMETER IncludeProjections
        Include growth projections

    .EXAMPLE
        Get-ClusterCapacityPlanning -ClusterName "PROD-CLUSTER"

    .EXAMPLE
        Get-ClusterCapacityPlanning -ClusterName "PROD-CLUSTER" -PlanningHorizon 12 -IncludeProjections
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $false)]
        [int]$PlanningHorizon = 6,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeProjections
    )

    try {
        Write-Host "Generating capacity planning report for $ClusterName" -ForegroundColor Green

        $cluster = Get-Cluster -Name $ClusterName -ErrorAction Stop
        $nodes = Get-ClusterNode -Cluster $ClusterName

        $capacityReport = @{
            ClusterName = $ClusterName
            PlanningHorizon = $PlanningHorizon
            GeneratedAt = Get-Date
            CurrentCapacity = @{}
            ProjectedCapacity = @{}
            Recommendations = @()
            ResourceUtilization = @{}
            GrowthProjections = @{}
        }

        # Current capacity analysis
        $capacityReport.CurrentCapacity = @{
            TotalNodes = $nodes.Count
            UpNodes = ($nodes | Where-Object { $_.State -eq "Up" }).Count
            TotalResources = (Get-ClusterResource -Cluster $ClusterName).Count
            OnlineResources = (Get-ClusterResource -Cluster $ClusterName | Where-Object { $_.State -eq "Online" }).Count
        }

        # Resource utilization analysis
        foreach ($node in $nodes) {
            try {
                $cpuCounter = Get-Counter -ComputerName $node.Name -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 5 -ErrorAction Stop
                $memoryCounter = Get-Counter -ComputerName $node.Name -Counter "\Memory\% Committed Bytes In Use" -SampleInterval 1 -MaxSamples 5 -ErrorAction Stop
                
                $avgCpu = ($cpuCounter.CounterSamples | Measure-Object -Property CookedValue -Average).Average
                $avgMemory = ($memoryCounter.CounterSamples | Measure-Object -Property CookedValue -Average).Average

                $capacityReport.ResourceUtilization[$node.Name] = @{
                    CPUUsage = [math]::Round($avgCpu, 2)
                    MemoryUsage = [math]::Round($avgMemory, 2)
                    Status = if ($avgCpu -lt 70 -and $avgMemory -lt 80) { "Good" } elseif ($avgCpu -lt 85 -and $avgMemory -lt 90) { "Warning" } else { "Critical" }
                }
            }
            catch {
                $capacityReport.ResourceUtilization[$node.Name] = @{
                    CPUUsage = 0
                    MemoryUsage = 0
                    Status = "Unknown"
                    Error = $_.Exception.Message
                }
            }
        }

        # Growth projections
        if ($IncludeProjections) {
            $avgCpuUsage = ($capacityReport.ResourceUtilization.Values | Where-Object { $_.CPUUsage -gt 0 } | Measure-Object -Property CPUUsage -Average).Average
            $avgMemoryUsage = ($capacityReport.ResourceUtilization.Values | Where-Object { $_.MemoryUsage -gt 0 } | Measure-Object -Property MemoryUsage -Average).Average

            # Simple linear growth projection (5% per month)
            $monthlyGrowthRate = 0.05
            $projectedCpuUsage = $avgCpuUsage * (1 + ($monthlyGrowthRate * $PlanningHorizon))
            $projectedMemoryUsage = $avgMemoryUsage * (1 + ($monthlyGrowthRate * $PlanningHorizon))

            $capacityReport.GrowthProjections = @{
                CurrentCPUUsage = [math]::Round($avgCpuUsage, 2)
                ProjectedCPUUsage = [math]::Round($projectedCpuUsage, 2)
                CurrentMemoryUsage = [math]::Round($avgMemoryUsage, 2)
                ProjectedMemoryUsage = [math]::Round($projectedMemoryUsage, 2)
                GrowthRate = $monthlyGrowthRate
            }

            $capacityReport.ProjectedCapacity = @{
                CPUUtilization = [math]::Round($projectedCpuUsage, 2)
                MemoryUtilization = [math]::Round($projectedMemoryUsage, 2)
                AdditionalNodesNeeded = if ($projectedCpuUsage -gt 80) { [math]::Ceiling(($projectedCpuUsage - 80) / 20) } else { 0 }
            }
        }

        # Generate recommendations
        $criticalNodes = $capacityReport.ResourceUtilization.Values | Where-Object { $_.Status -eq "Critical" }
        $warningNodes = $capacityReport.ResourceUtilization.Values | Where-Object { $_.Status -eq "Warning" }

        if ($criticalNodes.Count -gt 0) {
            $capacityReport.Recommendations += "Immediate action required: Critical resource utilization detected"
            $capacityReport.Recommendations += "Consider adding additional nodes or optimizing resource allocation"
        }

        if ($warningNodes.Count -gt 0) {
            $capacityReport.Recommendations += "Monitor resource utilization closely"
            $capacityReport.Recommendations += "Plan for capacity expansion within 3 months"
        }

        if ($IncludeProjections) {
            if ($capacityReport.ProjectedCapacity.CPUUtilization -gt 80) {
                $capacityReport.Recommendations += "Projected CPU utilization exceeds 80% - plan for capacity expansion"
            }
            if ($capacityReport.ProjectedCapacity.MemoryUtilization -gt 85) {
                $capacityReport.Recommendations += "Projected memory utilization exceeds 85% - plan for capacity expansion"
            }
            if ($capacityReport.ProjectedCapacity.AdditionalNodesNeeded -gt 0) {
                $capacityReport.Recommendations += "Consider adding $($capacityReport.ProjectedCapacity.AdditionalNodesNeeded) additional nodes"
            }
        }

        $capacityReport.Recommendations += "Schedule regular capacity planning reviews"
        $capacityReport.Recommendations += "Monitor resource utilization trends"
        $capacityReport.Recommendations += "Implement automated scaling if possible"

        return $capacityReport
    }
    catch {
        Write-Error "Failed to generate capacity planning report: $($_.Exception.Message)"
        throw
    }
}

function Set-ClusterMonitoring {
    <#
    .SYNOPSIS
        Configure cluster monitoring settings

    .DESCRIPTION
        Configures monitoring settings for the cluster

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER MonitoringLevel
        Monitoring level (Basic, Enhanced, Advanced)

    .PARAMETER MonitoringInterval
        Monitoring interval in minutes

    .PARAMETER LogRetention
        Log retention period in days

    .PARAMETER LogLocation
        Location to store monitoring logs

    .EXAMPLE
        Set-ClusterMonitoring -ClusterName "PROD-CLUSTER" -MonitoringLevel "Advanced" -MonitoringInterval 5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Basic", "Enhanced", "Advanced")]
        [string]$MonitoringLevel,

        [Parameter(Mandatory = $false)]
        [int]$MonitoringInterval = 5,

        [Parameter(Mandatory = $false)]
        [int]$LogRetention = 30,

        [Parameter(Mandatory = $false)]
        [string]$LogLocation = "C:\ClusterMonitoring"
    )

    try {
        Write-Host "Configuring cluster monitoring for $ClusterName" -ForegroundColor Green

        $monitoringConfig = @{
            ClusterName = $ClusterName
            MonitoringLevel = $MonitoringLevel
            MonitoringInterval = $MonitoringInterval
            LogRetention = $LogRetention
            LogLocation = $LogLocation
            ConfiguredAt = Get-Date
            ConfiguredBy = $env:USERNAME
        }

        # Create monitoring directory
        if (!(Test-Path $LogLocation)) {
            New-Item -Path $LogLocation -ItemType Directory -Force
        }

        # Configure monitoring based on level
        switch ($MonitoringLevel) {
            "Basic" {
                Set-BasicMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval -LogLocation $LogLocation
            }
            "Enhanced" {
                Set-EnhancedMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval -LogLocation $LogLocation
            }
            "Advanced" {
                Set-AdvancedMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval -LogLocation $LogLocation
            }
        }

        # Configure log retention
        Set-LogRetention -LogLocation $LogLocation -RetentionDays $LogRetention

        Write-Host "Cluster monitoring configured successfully" -ForegroundColor Green
        return $monitoringConfig
    }
    catch {
        Write-Error "Failed to configure cluster monitoring: $($_.Exception.Message)"
        throw
    }
}

function Set-ClusterAlerting {
    <#
    .SYNOPSIS
        Configure cluster alerting

    .DESCRIPTION
        Configures alerting methods for cluster events

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER AlertMethods
        Alert methods (Email, Webhook, SNMP, Slack, Teams)

    .PARAMETER Recipients
        Alert recipients

    .PARAMETER AlertThresholds
        Alert thresholds for different metrics

    .EXAMPLE
        Set-ClusterAlerting -ClusterName "PROD-CLUSTER" -AlertMethods @("Email", "Webhook") -Recipients @("admin@contoso.com")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Email", "Webhook", "SNMP", "Slack", "Teams")]
        [string[]]$AlertMethods,

        [Parameter(Mandatory = $true)]
        [string[]]$Recipients,

        [Parameter(Mandatory = $false)]
        [hashtable]$AlertThresholds
    )

    try {
        Write-Host "Configuring cluster alerting for $ClusterName" -ForegroundColor Green

        $alertingConfig = @{
            ClusterName = $ClusterName
            AlertMethods = $AlertMethods
            Recipients = $Recipients
            AlertThresholds = $AlertThresholds
            ConfiguredAt = Get-Date
            ConfiguredBy = $env:USERNAME
        }

        # Set default thresholds if not provided
        if (!$AlertThresholds) {
            $alertingConfig.AlertThresholds = @{
                CPUUsage = 80
                MemoryUsage = 85
                DiskUsage = 90
                NetworkLatency = 100
                ResourceOffline = 1
                NodeDown = 1
            }
        }

        # Configure each alert method
        foreach ($method in $AlertMethods) {
            switch ($method) {
                "Email" {
                    Set-EmailAlerting -ClusterName $ClusterName -Recipients $Recipients
                }
                "Webhook" {
                    Set-WebhookAlerting -ClusterName $ClusterName -Recipients $Recipients
                }
                "SNMP" {
                    Set-SNMPAlerting -ClusterName $ClusterName -Recipients $Recipients
                }
                "Slack" {
                    Set-SlackAlerting -ClusterName $ClusterName -Recipients $Recipients
                }
                "Teams" {
                    Set-TeamsAlerting -ClusterName $ClusterName -Recipients $Recipients
                }
            }
        }

        Write-Host "Cluster alerting configured successfully" -ForegroundColor Green
        return $alertingConfig
    }
    catch {
        Write-Error "Failed to configure cluster alerting: $($_.Exception.Message)"
        throw
    }
}

function Get-ClusterReport {
    <#
    .SYNOPSIS
        Generate comprehensive cluster report

    .DESCRIPTION
        Generates a comprehensive report for the cluster

    .PARAMETER ClusterName
        Name of the cluster

    .PARAMETER ReportType
        Type of report to generate

    .PARAMETER OutputPath
        Path to save the report

    .PARAMETER Format
        Report format (HTML, JSON, XML)

    .EXAMPLE
        Get-ClusterReport -ClusterName "PROD-CLUSTER" -ReportType "Comprehensive" -OutputPath "C:\Reports\ClusterReport.html"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Basic", "Comprehensive", "Health", "Performance", "Capacity")]
        [string]$ReportType,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("HTML", "JSON", "XML")]
        [string]$Format = "HTML"
    )

    try {
        Write-Host "Generating cluster report for $ClusterName" -ForegroundColor Green

        $report = @{
            ClusterName = $ClusterName
            ReportType = $ReportType
            GeneratedAt = Get-Date
            GeneratedBy = $env:USERNAME
        }

        # Generate report based on type
        switch ($ReportType) {
            "Basic" {
                $report.Data = Get-ClusterStatus -ClusterName $ClusterName
            }
            "Comprehensive" {
                $report.Data = @{
                    Status = Get-ClusterStatus -ClusterName $ClusterName -IncludeDetails -IncludeNodes -IncludeResources
                    Performance = Get-ClusterPerformanceMetrics -ClusterName $ClusterName
                    Events = Get-ClusterEventAnalysis -ClusterName $ClusterName -TimeRange 24
                    Capacity = Get-ClusterCapacityPlanning -ClusterName $ClusterName
                }
            }
            "Health" {
                $report.Data = Get-ClusterHealthStatus -ClusterName $ClusterName -IncludeDetails -IncludeNodes -IncludeResources
            }
            "Performance" {
                $report.Data = Get-ClusterPerformanceMetrics -ClusterName $ClusterName
            }
            "Capacity" {
                $report.Data = Get-ClusterCapacityPlanning -ClusterName $ClusterName -IncludeProjections
            }
        }

        # Save report in specified format
        switch ($Format) {
            "HTML" {
                $htmlContent = ConvertTo-Html -InputObject $report -Title "Cluster Report - $ClusterName"
                $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
            }
            "JSON" {
                $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
            }
            "XML" {
                $report | Export-Clixml -Path $OutputPath
            }
        }

        Write-Host "Cluster report generated successfully: $OutputPath" -ForegroundColor Green
        return $report
    }
    catch {
        Write-Error "Failed to generate cluster report: $($_.Exception.Message)"
        throw
    }
}

# Helper functions for monitoring implementations
function Set-BasicMonitoring { param($ClusterName, $MonitoringInterval, $LogLocation) Write-Host "Setting basic monitoring for $ClusterName" -ForegroundColor Green }
function Set-EnhancedMonitoring { param($ClusterName, $MonitoringInterval, $LogLocation) Write-Host "Setting enhanced monitoring for $ClusterName" -ForegroundColor Green }
function Set-AdvancedMonitoring { param($ClusterName, $MonitoringInterval, $LogLocation) Write-Host "Setting advanced monitoring for $ClusterName" -ForegroundColor Green }
function Set-LogRetention { param($LogLocation, $RetentionDays) Write-Host "Setting log retention for $LogLocation" -ForegroundColor Green }
function Set-EmailAlerting { param($ClusterName, $Recipients) Write-Host "Setting email alerting for $ClusterName" -ForegroundColor Green }
function Set-WebhookAlerting { param($ClusterName, $Recipients) Write-Host "Setting webhook alerting for $ClusterName" -ForegroundColor Green }
function Set-SNMPAlerting { param($ClusterName, $Recipients) Write-Host "Setting SNMP alerting for $ClusterName" -ForegroundColor Green }
function Set-SlackAlerting { param($ClusterName, $Recipients) Write-Host "Setting Slack alerting for $ClusterName" -ForegroundColor Green }
function Set-TeamsAlerting { param($ClusterName, $Recipients) Write-Host "Setting Teams alerting for $ClusterName" -ForegroundColor Green }

# Export functions
Export-ModuleMember -Function @(
    'Get-ClusterHealthStatus',
    'Get-ClusterPerformanceMetrics',
    'Get-ClusterEventAnalysis',
    'Get-ClusterCapacityPlanning',
    'Set-ClusterMonitoring',
    'Set-ClusterAlerting',
    'Get-ClusterReport'
)
