#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hyper-V Monitoring Management Module

.DESCRIPTION
    Monitoring and performance functions for Windows Hyper-V virtualization.
    Provides resource utilization tracking, performance metrics collection,
    health monitoring, alerting, notifications, capacity planning, and reporting.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This module provides Hyper-V monitoring capabilities including:
    - Resource utilization tracking
    - Performance metrics collection
    - Health monitoring
    - Alerting and notifications
    - Capacity planning
    - Reporting
    - Event log monitoring
    - Storage monitoring
    - Network monitoring
    - VM lifecycle monitoring
#>

# Module metadata
$ModuleName = "HyperV-Monitoring"
$ModuleVersion = "1.0.0"

# Import required modules
Import-Module Hyper-V -ErrorAction Stop
Import-Module PerformanceCounter -ErrorAction Stop

# Resource Monitoring Functions

function Get-HyperVResourceUtilization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("CPU", "Memory", "Network", "Disk", "All")]
        [string]$ResourceType = "All"
    )
    
    try {
        Write-Verbose "Getting Hyper-V resource utilization"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        if ($VMName) {
            $vms = @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop)
        } else {
            $vms = Get-VM -VMHost $host
        }
        
        $resourceData = @()
        
        foreach ($vm in $vms) {
            $vmData = @{
                VMName = $vm.Name
                HostName = $HostName
                Timestamp = Get-Date
                CPU = @{}
                Memory = @{}
                Network = @{}
                Disk = @{}
            }
            
            # Get CPU utilization
            if ($ResourceType -in @("CPU", "All")) {
                $cpuCounters = Get-Counter -Counter "\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time" -MaxSamples 1 -ErrorAction SilentlyContinue
                if ($cpuCounters) {
                    $vmData.CPU = @{
                        TotalRunTime = $cpuCounters.CounterSamples[0].CookedValue
                        ProcessorCount = $vm.ProcessorCount
                    }
                }
            }
            
            # Get memory utilization
            if ($ResourceType -in @("Memory", "All")) {
                $vmData.Memory = @{
                    Assigned = $vm.MemoryAssigned
                    Startup = $vm.MemoryStartup
                    Minimum = $vm.MemoryMinimum
                    Maximum = $vm.MemoryMaximum
                    DynamicMemoryEnabled = $vm.DynamicMemoryEnabled
                }
            }
            
            # Get network utilization
            if ($ResourceType -in @("Network", "All")) {
                $networkAdapters = Get-VMNetworkAdapter -VM $vm
                $networkData = @()
                foreach ($adapter in $networkAdapters) {
                    $networkData += @{
                        Name = $adapter.Name
                        SwitchName = $adapter.SwitchName
                        MacAddress = $adapter.MacAddress
                        IPAddresses = $adapter.IPAddresses
                    }
                }
                $vmData.Network = $networkData
            }
            
            # Get disk utilization
            if ($ResourceType -in @("Disk", "All")) {
                $hardDrives = Get-VMHardDiskDrive -VM $vm
                $diskData = @()
                foreach ($drive in $hardDrives) {
                    $diskData += @{
                        Path = $drive.Path
                        ControllerType = $drive.ControllerType
                        ControllerNumber = $drive.ControllerNumber
                        ControllerLocation = $drive.ControllerLocation
                    }
                }
                $vmData.Disk = $diskData
            }
            
            $resourceData += $vmData
        }
        
        Write-Verbose "Resource utilization retrieved successfully"
        return $resourceData
    }
    catch {
        Write-Error "Failed to get resource utilization: $($_.Exception.Message)"
        throw
    }
}

function Get-HyperVPerformanceMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60,
        
        [Parameter(Mandatory = $false)]
        [int]$SampleIntervalSeconds = 30
    )
    
    try {
        Write-Verbose "Getting Hyper-V performance metrics"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        if ($VMName) {
            $vms = @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop)
        } else {
            $vms = Get-VM -VMHost $host
        }
        
        $performanceData = @()
        
        foreach ($vm in $vms) {
            $vmMetrics = @{
                VMName = $vm.Name
                HostName = $HostName
                Timestamp = Get-Date
                Metrics = @{}
            }
            
            # Get performance counters
            $counters = @(
                "\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time",
                "\Hyper-V Hypervisor Root Virtual Processor(_Total)\% Total Run Time",
                "\Hyper-V Dynamic Memory VM(*)\Available Memory",
                "\Hyper-V Dynamic Memory VM(*)\Guest Visible Physical Memory"
            )
            
            $counterData = Get-Counter -Counter $counters -MaxSamples 1 -ErrorAction SilentlyContinue
            
            if ($counterData) {
                $vmMetrics.Metrics = @{
                    CPUTotalRunTime = $counterData.CounterSamples | Where-Object { $_.Path -like "*Logical Processor*" } | Select-Object -ExpandProperty CookedValue
                    RootVPTotalRunTime = $counterData.CounterSamples | Where-Object { $_.Path -like "*Root Virtual Processor*" } | Select-Object -ExpandProperty CookedValue
                    AvailableMemory = $counterData.CounterSamples | Where-Object { $_.Path -like "*Available Memory*" } | Select-Object -ExpandProperty CookedValue
                    GuestVisibleMemory = $counterData.CounterSamples | Where-Object { $_.Path -like "*Guest Visible Physical Memory*" } | Select-Object -ExpandProperty CookedValue
                }
            }
            
            $performanceData += $vmMetrics
        }
        
        Write-Verbose "Performance metrics retrieved successfully"
        return $performanceData
    }
    catch {
        Write-Error "Failed to get performance metrics: $($_.Exception.Message)"
        throw
    }
}

# Health Monitoring Functions

function Get-HyperVHealthStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeVMs,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeHost
    )
    
    try {
        Write-Verbose "Getting Hyper-V health status"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        $healthStatus = @{
            HostName = $HostName
            Timestamp = Get-Date
            OverallHealth = "Healthy"
            HostHealth = @{}
            VMHealth = @()
            Issues = @()
        }
        
        # Get host health
        if ($IncludeHost) {
            $hostHealth = @{
                Name = $host.Name
                State = $host.State
                Version = $host.Version
                LogicalProcessorCount = $host.LogicalProcessorCount
                TotalMemory = $host.TotalMemory
                FreeMemory = $host.FreeMemory
                VirtualMachinePath = $host.VirtualMachinePath
                VirtualHardDiskPath = $host.VirtualHardDiskPath
                EnableEnhancedSessionMode = $host.EnableEnhancedSessionMode
            }
            
            # Check for host issues
            if ($host.State -ne "Enabled") {
                $healthStatus.Issues += "Host is not in enabled state"
                $healthStatus.OverallHealth = "Warning"
            }
            
            if ($host.FreeMemory -lt ($host.TotalMemory * 0.1)) {
                $healthStatus.Issues += "Low memory on host"
                $healthStatus.OverallHealth = "Warning"
            }
            
            $healthStatus.HostHealth = $hostHealth
        }
        
        # Get VM health
        if ($IncludeVMs) {
            $vms = if ($VMName) { @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop) } else { Get-VM -VMHost $host }
            
            foreach ($vm in $vms) {
                $vmHealth = @{
                    Name = $vm.Name
                    State = $vm.State
                    Status = $vm.Status
                    Uptime = $vm.Uptime
                    ProcessorCount = $vm.ProcessorCount
                    MemoryAssigned = $vm.MemoryAssigned
                    MemoryStartup = $vm.MemoryStartup
                    IsShielded = $vm.IsShielded
                    HasSecureBoot = $vm.HasSecureBoot
                    HasTPM = $vm.HasTPM
                }
                
                # Check for VM issues
                if ($vm.State -ne "Running" -and $vm.State -ne "Off") {
                    $healthStatus.Issues += "VM $($vm.Name) is in $($vm.State) state"
                    $healthStatus.OverallHealth = "Warning"
                }
                
                $healthStatus.VMHealth += $vmHealth
            }
        }
        
        # Determine overall health
        if ($healthStatus.Issues.Count -gt 0) {
            $criticalIssues = $healthStatus.Issues | Where-Object { $_ -like "*Critical*" -or $_ -like "*Failed*" }
            if ($criticalIssues.Count -gt 0) {
                $healthStatus.OverallHealth = "Critical"
            }
        }
        
        Write-Verbose "Health status retrieved successfully"
        return $healthStatus
    }
    catch {
        Write-Error "Failed to get health status: $($_.Exception.Message)"
        throw
    }
}

# Event Log Monitoring Functions

function Get-HyperVEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Error", "Warning", "Information")]
        [string]$LogLevel = "All",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 100,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$StartTime,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$EndTime
    )
    
    try {
        Write-Verbose "Getting Hyper-V event logs"
        
        $eventLogs = @(
            "Microsoft-Windows-Hyper-V-VMMS-Admin",
            "Microsoft-Windows-Hyper-V-VMMS-Operational",
            "Microsoft-Windows-Hyper-V-Hypervisor-Admin",
            "Microsoft-Windows-Hyper-V-Hypervisor-Operational"
        )
        
        $events = @()
        
        foreach ($logName in $eventLogs) {
            try {
                $logEvents = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                
                if ($StartTime) {
                    $logEvents = $logEvents | Where-Object { $_.TimeCreated -ge $StartTime }
                }
                if ($EndTime) {
                    $logEvents = $logEvents | Where-Object { $_.TimeCreated -le $EndTime }
                }
                
                foreach ($event in $logEvents) {
                    $eventData = @{
                        LogName = $logName
                        TimeCreated = $event.TimeCreated
                        Level = $event.LevelDisplayName
                        Id = $event.Id
                        Message = $event.Message
                        MachineName = $event.MachineName
                    }
                    
                    # Filter by log level
                    if ($LogLevel -eq "All" -or $event.LevelDisplayName -eq $LogLevel) {
                        $events += $eventData
                    }
                }
            }
            catch {
                Write-Warning "Could not access event log: $logName"
            }
        }
        
        # Sort by time created (newest first)
        $events = $events | Sort-Object TimeCreated -Descending
        
        Write-Verbose "Event logs retrieved successfully"
        return $events
    }
    catch {
        Write-Error "Failed to get event logs: $($_.Exception.Message)"
        throw
    }
}

# Storage Monitoring Functions

function Get-HyperVStorageUtilization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeVHDs,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCheckpoints
    )
    
    try {
        Write-Verbose "Getting Hyper-V storage utilization"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        if ($VMName) {
            $vms = @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop)
        } else {
            $vms = Get-VM -VMHost $host
        }
        
        $storageData = @{
            HostName = $HostName
            Timestamp = Get-Date
            VMs = @()
            TotalVHDSize = 0
            TotalVHDUsed = 0
            TotalCheckpointSize = 0
        }
        
        foreach ($vm in $vms) {
            $vmStorage = @{
                VMName = $vm.Name
                VHDs = @()
                Checkpoints = @()
                TotalVHDSize = 0
                TotalVHDUsed = 0
                TotalCheckpointSize = 0
            }
            
            # Get VHD information
            if ($IncludeVHDs) {
                $hardDrives = Get-VMHardDiskDrive -VM $vm
                foreach ($drive in $hardDrives) {
                    if (Test-Path $drive.Path) {
                        $vhdInfo = Get-VHD -Path $drive.Path -ErrorAction SilentlyContinue
                        if ($vhdInfo) {
                            $vhdData = @{
                                Path = $drive.Path
                                Size = $vhdInfo.Size
                                FileSize = $vhdInfo.FileSize
                                Type = $vhdInfo.VhdType
                                ParentPath = $vhdInfo.ParentPath
                            }
                            $vmStorage.VHDs += $vhdData
                            $vmStorage.TotalVHDSize += $vhdInfo.Size
                            $vmStorage.TotalVHDUsed += $vhdInfo.FileSize
                        }
                    }
                }
            }
            
            # Get checkpoint information
            if ($IncludeCheckpoints) {
                $checkpoints = Get-VMSnapshot -VM $vm
                foreach ($checkpoint in $checkpoints) {
                    $checkpointData = @{
                        Name = $checkpoint.Name
                        CreationTime = $checkpoint.CreationTime
                        ParentSnapshotName = $checkpoint.ParentSnapshotName
                        SnapshotType = $checkpoint.SnapshotType
                    }
                    $vmStorage.Checkpoints += $checkpointData
                }
            }
            
            $storageData.VMs += $vmStorage
            $storageData.TotalVHDSize += $vmStorage.TotalVHDSize
            $storageData.TotalVHDUsed += $vmStorage.TotalVHDUsed
        }
        
        Write-Verbose "Storage utilization retrieved successfully"
        return $storageData
    }
    catch {
        Write-Error "Failed to get storage utilization: $($_.Exception.Message)"
        throw
    }
}

# Network Monitoring Functions

function Get-HyperVNetworkUtilization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60
    )
    
    try {
        Write-Verbose "Getting Hyper-V network utilization"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        if ($VMName) {
            $vms = @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop)
        } else {
            $vms = Get-VM -VMHost $host
        }
        
        $networkData = @{
            HostName = $HostName
            Timestamp = Get-Date
            Switches = @()
            VMs = @()
        }
        
        # Get switch information
        $switches = Get-VMSwitch -VMHost $host
        foreach ($switch in $switches) {
            $switchData = @{
                Name = $switch.Name
                SwitchType = $switch.SwitchType
                NetAdapterInterfaceDescription = $switch.NetAdapterInterfaceDescription
                AllowManagementOS = $switch.AllowManagementOS
                EnableIov = $switch.EnableIov
            }
            $networkData.Switches += $switchData
        }
        
        # Get VM network information
        foreach ($vm in $vms) {
            $networkAdapters = Get-VMNetworkAdapter -VM $vm
            $vmNetworkData = @{
                VMName = $vm.Name
                NetworkAdapters = @()
            }
            
            foreach ($adapter in $networkAdapters) {
                $adapterData = @{
                    Name = $adapter.Name
                    SwitchName = $adapter.SwitchName
                    MacAddress = $adapter.MacAddress
                    IPAddresses = $adapter.IPAddresses
                    DhcpGuard = $adapter.DhcpGuard
                    RouterGuard = $adapter.RouterGuard
                    MacAddressSpoofing = $adapter.MacAddressSpoofing
                }
                $vmNetworkData.NetworkAdapters += $adapterData
            }
            
            $networkData.VMs += $vmNetworkData
        }
        
        Write-Verbose "Network utilization retrieved successfully"
        return $networkData
    }
    catch {
        Write-Error "Failed to get network utilization: $($_.Exception.Message)"
        throw
    }
}

# Alerting Functions

function Set-HyperVAlerting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AlertThresholds,
        
        [Parameter(Mandatory = $false)]
        [string]$EmailRecipients,
        
        [Parameter(Mandatory = $false)]
        [string]$SMTPServer,
        
        [Parameter(Mandatory = $false)]
        [string]$WebhookURL,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableCPUAlerts,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableMemoryAlerts,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableDiskAlerts,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableNetworkAlerts
    )
    
    try {
        Write-Verbose "Configuring Hyper-V alerting"
        
        # Default thresholds
        $defaultThresholds = @{
            CPUUsage = 80
            MemoryUsage = 85
            DiskUsage = 90
            NetworkUsage = 75
            VMState = "Critical"
        }
        
        if ($AlertThresholds) {
            $thresholds = $defaultThresholds + $AlertThresholds
        } else {
            $thresholds = $defaultThresholds
        }
        
        # Create alerting configuration
        $alertingConfig = @{
            HostName = $HostName
            Thresholds = $thresholds
            EmailRecipients = $EmailRecipients
            SMTPServer = $SMTPServer
            WebhookURL = $WebhookURL
            EnabledAlerts = @{
                CPU = $EnableCPUAlerts
                Memory = $EnableMemoryAlerts
                Disk = $EnableDiskAlerts
                Network = $EnableNetworkAlerts
            }
            LastAlertTime = $null
        }
        
        # Save configuration
        $configPath = "C:\HyperVMonitoring\AlertingConfig.json"
        $configDir = Split-Path $configPath -Parent
        if (-not (Test-Path $configDir)) {
            New-Item -Path $configDir -ItemType Directory -Force
        }
        
        $alertingConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        
        Write-Verbose "Hyper-V alerting configured successfully"
        return $alertingConfig
    }
    catch {
        Write-Error "Failed to configure alerting: $($_.Exception.Message)"
        throw
    }
}

# Capacity Planning Functions

function Get-HyperVCapacityPlanning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [int]$PlanningHorizonDays = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTrends,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRecommendations
    )
    
    try {
        Write-Verbose "Generating Hyper-V capacity planning report"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        $vms = Get-VM -VMHost $host
        
        $capacityData = @{
            HostName = $HostName
            Timestamp = Get-Date
            PlanningHorizonDays = $PlanningHorizonDays
            HostCapacity = @{
                LogicalProcessorCount = $host.LogicalProcessorCount
                TotalMemory = $host.TotalMemory
                FreeMemory = $host.FreeMemory
                MemoryUtilization = (($host.TotalMemory - $host.FreeMemory) / $host.TotalMemory) * 100
            }
            VMCapacity = @{
                TotalVMs = $vms.Count
                RunningVMs = ($vms | Where-Object { $_.State -eq "Running" }).Count
                TotalAssignedMemory = ($vms | Measure-Object -Property MemoryAssigned -Sum).Sum
                TotalAssignedProcessors = ($vms | Measure-Object -Property ProcessorCount -Sum).Sum
            }
            Recommendations = @()
        }
        
        # Calculate capacity utilization
        $memoryUtilization = ($capacityData.VMCapacity.TotalAssignedMemory / $capacityData.HostCapacity.TotalMemory) * 100
        $processorUtilization = ($capacityData.VMCapacity.TotalAssignedProcessors / $capacityData.HostCapacity.LogicalProcessorCount) * 100
        
        $capacityData.HostCapacity.MemoryUtilization = $memoryUtilization
        $capacityData.HostCapacity.ProcessorUtilization = $processorUtilization
        
        # Generate recommendations
        if ($IncludeRecommendations) {
            if ($memoryUtilization -gt 80) {
                $capacityData.Recommendations += "High memory utilization detected. Consider adding more RAM or migrating VMs."
            }
            if ($processorUtilization -gt 80) {
                $capacityData.Recommendations += "High processor utilization detected. Consider adding more processors or migrating VMs."
            }
            if ($capacityData.HostCapacity.FreeMemory -lt ($capacityData.HostCapacity.TotalMemory * 0.1)) {
                $capacityData.Recommendations += "Low free memory on host. Consider optimizing VM memory allocation."
            }
        }
        
        Write-Verbose "Capacity planning report generated successfully"
        return $capacityData
    }
    catch {
        Write-Error "Failed to generate capacity planning report: $($_.Exception.Message)"
        throw
    }
}

# Reporting Functions

function Get-HyperVMonitoringReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Enhanced", "Comprehensive")]
        [string]$ReportType = "Enhanced",
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("HTML", "XML", "JSON")]
        [string]$Format = "HTML"
    )
    
    try {
        Write-Verbose "Generating Hyper-V monitoring report"
        
        $report = @{
            HostName = $HostName
            ReportDate = Get-Date
            ReportType = $ReportType
            HostInfo = @{}
            VMInfo = @()
            ResourceUtilization = @{}
            PerformanceMetrics = @{}
            HealthStatus = @{}
            EventLogs = @()
            StorageUtilization = @{}
            NetworkUtilization = @{}
            CapacityPlanning = @{}
        }
        
        # Get host information
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        $report.HostInfo = @{
            Name = $host.Name
            Version = $host.Version
            LogicalProcessorCount = $host.LogicalProcessorCount
            TotalMemory = $host.TotalMemory
            FreeMemory = $host.FreeMemory
            VirtualMachinePath = $host.VirtualMachinePath
            VirtualHardDiskPath = $host.VirtualHardDiskPath
        }
        
        # Get VM information
        $vms = Get-VM -VMHost $host
        foreach ($vm in $vms) {
            $vmInfo = @{
                Name = $vm.Name
                State = $vm.State
                Status = $vm.Status
                Uptime = $vm.Uptime
                ProcessorCount = $vm.ProcessorCount
                MemoryAssigned = $vm.MemoryAssigned
                MemoryStartup = $vm.MemoryStartup
                IsShielded = $vm.IsShielded
                HasSecureBoot = $vm.HasSecureBoot
                HasTPM = $vm.HasTPM
            }
            $report.VMInfo += $vmInfo
        }
        
        # Get resource utilization
        if ($ReportType -in @("Enhanced", "Comprehensive")) {
            $report.ResourceUtilization = Get-HyperVResourceUtilization -HostName $HostName
        }
        
        # Get performance metrics
        if ($ReportType -eq "Comprehensive") {
            $report.PerformanceMetrics = Get-HyperVPerformanceMetrics -HostName $HostName
        }
        
        # Get health status
        $report.HealthStatus = Get-HyperVHealthStatus -HostName $HostName -IncludeDetails -IncludeVMs -IncludeHost
        
        # Get event logs
        if ($ReportType -in @("Enhanced", "Comprehensive")) {
            $report.EventLogs = Get-HyperVEventLogs -HostName $HostName -MaxEvents 50
        }
        
        # Get storage utilization
        if ($ReportType -eq "Comprehensive") {
            $report.StorageUtilization = Get-HyperVStorageUtilization -HostName $HostName -IncludeVHDs -IncludeCheckpoints
        }
        
        # Get network utilization
        if ($ReportType -eq "Comprehensive") {
            $report.NetworkUtilization = Get-HyperVNetworkUtilization -HostName $HostName
        }
        
        # Get capacity planning
        if ($ReportType -eq "Comprehensive") {
            $report.CapacityPlanning = Get-HyperVCapacityPlanning -HostName $HostName -IncludeRecommendations
        }
        
        # Output report
        if ($OutputPath) {
            switch ($Format) {
                "HTML" {
                    $htmlReport = $report | ConvertTo-Html -Title "Hyper-V Monitoring Report"
                    $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
                }
                "XML" {
                    $report | Export-Clixml -Path $OutputPath
                }
                "JSON" {
                    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
                }
            }
        }
        
        Write-Verbose "Hyper-V monitoring report generated successfully"
        return $report
    }
    catch {
        Write-Error "Failed to generate monitoring report: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Get-HyperVResourceUtilization',
    'Get-HyperVPerformanceMetrics',
    'Get-HyperVHealthStatus',
    'Get-HyperVEventLogs',
    'Get-HyperVStorageUtilization',
    'Get-HyperVNetworkUtilization',
    'Set-HyperVAlerting',
    'Get-HyperVCapacityPlanning',
    'Get-HyperVMonitoringReport'
)
