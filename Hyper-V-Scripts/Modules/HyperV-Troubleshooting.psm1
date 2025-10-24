#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hyper-V Troubleshooting Management Module

.DESCRIPTION
    Diagnostics and troubleshooting functions for Windows Hyper-V virtualization.
    Provides VM diagnostics, event log analysis, performance troubleshooting,
    migration troubleshooting, recovery operations, and health checks.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This module provides Hyper-V troubleshooting capabilities including:
    - VM diagnostics
    - Event log analysis
    - Performance troubleshooting
    - Migration troubleshooting
    - Recovery operations
    - Health checks
    - Storage diagnostics
    - Network diagnostics
    - Integration services diagnostics
    - Checkpoint diagnostics
#>

# Module metadata
$ModuleName = "HyperV-Troubleshooting"
$ModuleVersion = "1.0.0"

# Import required modules
Import-Module Hyper-V -ErrorAction Stop
Import-Module PerformanceCounter -ErrorAction Stop

# VM Diagnostics Functions

function Test-HyperVMDiagnostics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Standard", "Comprehensive")]
        [string]$DiagnosticLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformance,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeStorage,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetwork,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeIntegrationServices,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCheckpoints
    )
    
    try {
        Write-Verbose "Running VM diagnostics for: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        $diagnostics = @{
            VMName = $VMName
            Timestamp = Get-Date
            DiagnosticLevel = $DiagnosticLevel
            OverallStatus = "Healthy"
            Issues = @()
            Recommendations = @()
            VMInfo = @{}
            Performance = @{}
            Storage = @{}
            Network = @{}
            IntegrationServices = @{}
            Checkpoints = @{}
        }
        
        # Get VM information
        $diagnostics.VMInfo = @{
            Name = $vm.Name
            State = $vm.State
            Status = $vm.Status
            Uptime = $vm.Uptime
            Generation = $vm.Generation
            ProcessorCount = $vm.ProcessorCount
            MemoryAssigned = $vm.MemoryAssigned
            MemoryStartup = $vm.MemoryStartup
            IsShielded = $vm.IsShielded
            HasSecureBoot = $vm.HasSecureBoot
            HasTPM = $vm.HasTPM
        }
        
        # Check VM state
        if ($vm.State -ne "Running" -and $vm.State -ne "Off") {
            $diagnostics.Issues += "VM is in $($vm.State) state"
            $diagnostics.OverallStatus = "Warning"
        }
        
        # Performance diagnostics
        if ($IncludePerformance -or $DiagnosticLevel -eq "Comprehensive") {
            try {
                $performanceCounters = Get-Counter -Counter "\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time" -MaxSamples 1 -ErrorAction SilentlyContinue
                if ($performanceCounters) {
                    $diagnostics.Performance = @{
                        CPUTotalRunTime = $performanceCounters.CounterSamples[0].CookedValue
                        Status = if ($performanceCounters.CounterSamples[0].CookedValue -gt 90) { "Warning" } else { "Healthy" }
                    }
                    
                    if ($performanceCounters.CounterSamples[0].CookedValue -gt 90) {
                        $diagnostics.Issues += "High CPU utilization detected"
                        $diagnostics.Recommendations += "Consider adding more processors or optimizing workload"
                    }
                }
            }
            catch {
                $diagnostics.Performance = @{ Status = "Error"; Error = $_.Exception.Message }
            }
        }
        
        # Storage diagnostics
        if ($IncludeStorage -or $DiagnosticLevel -eq "Comprehensive") {
            try {
                $hardDrives = Get-VMHardDiskDrive -VM $vm
                $storageIssues = @()
                
                foreach ($drive in $hardDrives) {
                    if (Test-Path $drive.Path) {
                        $vhdInfo = Get-VHD -Path $drive.Path -ErrorAction SilentlyContinue
                        if ($vhdInfo) {
                            $storageData = @{
                                Path = $drive.Path
                                Size = $vhdInfo.Size
                                FileSize = $vhdInfo.FileSize
                                Type = $vhdInfo.VhdType
                                Status = "Healthy"
                            }
                            
                            # Check for storage issues
                            if ($vhdInfo.FileSize -gt ($vhdInfo.Size * 0.9)) {
                                $storageIssues += "VHD $($drive.Path) is nearly full"
                                $storageData.Status = "Warning"
                            }
                            
                            $diagnostics.Storage += $storageData
                        } else {
                            $storageIssues += "Could not access VHD: $($drive.Path)"
                        }
                    } else {
                        $storageIssues += "VHD file not found: $($drive.Path)"
                    }
                }
                
                if ($storageIssues.Count -gt 0) {
                    $diagnostics.Issues += $storageIssues
                    $diagnostics.OverallStatus = "Warning"
                }
            }
            catch {
                $diagnostics.Storage = @{ Status = "Error"; Error = $_.Exception.Message }
            }
        }
        
        # Network diagnostics
        if ($IncludeNetwork -or $DiagnosticLevel -eq "Comprehensive") {
            try {
                $networkAdapters = Get-VMNetworkAdapter -VM $vm
                $networkIssues = @()
                
                foreach ($adapter in $networkAdapters) {
                    $networkData = @{
                        Name = $adapter.Name
                        SwitchName = $adapter.SwitchName
                        MacAddress = $adapter.MacAddress
                        IPAddresses = $adapter.IPAddresses
                        Status = "Healthy"
                    }
                    
                    # Check for network issues
                    if (-not $adapter.SwitchName) {
                        $networkIssues += "Network adapter $($adapter.Name) is not connected to a switch"
                        $networkData.Status = "Warning"
                    }
                    
                    if ($adapter.IPAddresses.Count -eq 0 -and $vm.State -eq "Running") {
                        $networkIssues += "Network adapter $($adapter.Name) has no IP addresses"
                        $networkData.Status = "Warning"
                    }
                    
                    $diagnostics.Network += $networkData
                }
                
                if ($networkIssues.Count -gt 0) {
                    $diagnostics.Issues += $networkIssues
                    $diagnostics.OverallStatus = "Warning"
                }
            }
            catch {
                $diagnostics.Network = @{ Status = "Error"; Error = $_.Exception.Message }
            }
        }
        
        # Integration services diagnostics
        if ($IncludeIntegrationServices -or $DiagnosticLevel -eq "Comprehensive") {
            try {
                $integrationServices = Get-VMIntegrationService -VM $vm
                $integrationIssues = @()
                
                foreach ($service in $integrationServices) {
                    $serviceData = @{
                        Name = $service.Name
                        Enabled = $service.Enabled
                        PrimaryOperationalStatus = $service.PrimaryOperationalStatus
                        SecondaryOperationalStatus = $service.SecondaryOperationalStatus
                        Status = "Healthy"
                    }
                    
                    # Check for integration service issues
                    if (-not $service.Enabled) {
                        $integrationIssues += "Integration service $($service.Name) is disabled"
                        $serviceData.Status = "Warning"
                    }
                    
                    if ($service.PrimaryOperationalStatus -ne "OK") {
                        $integrationIssues += "Integration service $($service.Name) has status: $($service.PrimaryOperationalStatus)"
                        $serviceData.Status = "Warning"
                    }
                    
                    $diagnostics.IntegrationServices += $serviceData
                }
                
                if ($integrationIssues.Count -gt 0) {
                    $diagnostics.Issues += $integrationIssues
                    $diagnostics.OverallStatus = "Warning"
                }
            }
            catch {
                $diagnostics.IntegrationServices = @{ Status = "Error"; Error = $_.Exception.Message }
            }
        }
        
        # Checkpoint diagnostics
        if ($IncludeCheckpoints -or $DiagnosticLevel -eq "Comprehensive") {
            try {
                $checkpoints = Get-VMSnapshot -VM $vm
                $checkpointIssues = @()
                
                foreach ($checkpoint in $checkpoints) {
                    $checkpointData = @{
                        Name = $checkpoint.Name
                        CreationTime = $checkpoint.CreationTime
                        ParentSnapshotName = $checkpoint.ParentSnapshotName
                        SnapshotType = $checkpoint.SnapshotType
                        Status = "Healthy"
                    }
                    
                    # Check for checkpoint issues
                    $age = (Get-Date) - $checkpoint.CreationTime
                    if ($age.Days -gt 30) {
                        $checkpointIssues += "Checkpoint $($checkpoint.Name) is older than 30 days"
                        $checkpointData.Status = "Warning"
                    }
                    
                    $diagnostics.Checkpoints += $checkpointData
                }
                
                if ($checkpointIssues.Count -gt 0) {
                    $diagnostics.Issues += $checkpointIssues
                    $diagnostics.Recommendations += "Consider removing old checkpoints to free up storage space"
                }
            }
            catch {
                $diagnostics.Checkpoints = @{ Status = "Error"; Error = $_.Exception.Message }
            }
        }
        
        # Determine overall status
        if ($diagnostics.Issues.Count -gt 0) {
            $criticalIssues = $diagnostics.Issues | Where-Object { $_ -like "*Critical*" -or $_ -like "*Failed*" }
            if ($criticalIssues.Count -gt 0) {
                $diagnostics.OverallStatus = "Critical"
            }
        }
        
        Write-Verbose "VM diagnostics completed for: $VMName"
        return $diagnostics
    }
    catch {
        Write-Error "Failed to run VM diagnostics: $($_.Exception.Message)"
        throw
    }
}

# Event Log Analysis Functions

function Analyze-HyperVEventLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Standard", "Comprehensive")]
        [string]$AnalysisType = "Standard",
        
        [Parameter(Mandatory = $false)]
        [int]$TimeRangeHours = 24,
        
        [Parameter(Mandatory = $false)]
        [switch]$GenerateReport
    )
    
    try {
        Write-Verbose "Analyzing Hyper-V event logs"
        
        $startTime = (Get-Date).AddHours(-$TimeRangeHours)
        $endTime = Get-Date
        
        $eventLogs = @(
            "Microsoft-Windows-Hyper-V-VMMS-Admin",
            "Microsoft-Windows-Hyper-V-VMMS-Operational",
            "Microsoft-Windows-Hyper-V-Hypervisor-Admin",
            "Microsoft-Windows-Hyper-V-Hypervisor-Operational"
        )
        
        $analysis = @{
            HostName = $HostName
            VMName = $VMName
            AnalysisType = $AnalysisType
            TimeRange = @{
                StartTime = $startTime
                EndTime = $endTime
                Hours = $TimeRangeHours
            }
            Timestamp = Get-Date
            EventsAnalyzed = 0
            CriticalEvents = 0
            ErrorEvents = 0
            WarningEvents = 0
            TopEvents = @()
            Issues = @()
            Recommendations = @()
        }
        
        $allEvents = @()
        
        foreach ($logName in $eventLogs) {
            try {
                $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue
                $filteredEvents = $events | Where-Object { $_.TimeCreated -ge $startTime -and $_.TimeCreated -le $endTime }
                
                foreach ($event in $filteredEvents) {
                    $eventData = @{
                        LogName = $logName
                        TimeCreated = $event.TimeCreated
                        Level = $event.LevelDisplayName
                        Id = $event.Id
                        Message = $event.Message
                        MachineName = $event.MachineName
                    }
                    
                    $allEvents += $eventData
                    
                    # Count events by level
                    switch ($event.LevelDisplayName) {
                        "Critical" { $analysis.CriticalEvents++ }
                        "Error" { $analysis.ErrorEvents++ }
                        "Warning" { $analysis.WarningEvents++ }
                    }
                }
            }
            catch {
                Write-Warning "Could not access event log: $logName"
            }
        }
        
        $analysis.EventsAnalyzed = $allEvents.Count
        
        # Analyze top events
        $topEvents = $allEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
        foreach ($eventGroup in $topEvents) {
            $topEvent = @{
                EventId = $eventGroup.Name
                Count = $eventGroup.Count
                Level = $eventGroup.Group[0].Level
                Message = $eventGroup.Group[0].Message
                LastOccurrence = ($eventGroup.Group | Sort-Object TimeCreated -Descending)[0].TimeCreated
            }
            $analysis.TopEvents += $topEvent
        }
        
        # Generate issues and recommendations
        if ($analysis.CriticalEvents -gt 0) {
            $analysis.Issues += "Critical events detected in Hyper-V logs"
            $analysis.Recommendations += "Investigate critical events immediately"
        }
        
        if ($analysis.ErrorEvents -gt 10) {
            $analysis.Issues += "High number of error events detected"
            $analysis.Recommendations += "Review error events and address underlying issues"
        }
        
        if ($analysis.WarningEvents -gt 50) {
            $analysis.Issues += "High number of warning events detected"
            $analysis.Recommendations += "Monitor warning events and consider proactive measures"
        }
        
        # VM-specific analysis
        if ($VMName) {
            $vmEvents = $allEvents | Where-Object { $_.Message -like "*$VMName*" }
            if ($vmEvents.Count -gt 0) {
                $analysis.Issues += "Events related to VM $VMName detected"
                $analysis.Recommendations += "Review VM-specific events for $VMName"
            }
        }
        
        Write-Verbose "Event log analysis completed"
        return $analysis
    }
    catch {
        Write-Error "Failed to analyze event logs: $($_.Exception.Message)"
        throw
    }
}

# Performance Troubleshooting Functions

function Test-HyperVPerformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60,
        
        [Parameter(Mandatory = $false)]
        [int]$SampleIntervalSeconds = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeCPU,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeMemory,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetwork,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisk
    )
    
    try {
        Write-Verbose "Testing Hyper-V performance"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        if ($VMName) {
            $vms = @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop)
        } else {
            $vms = Get-VM -VMHost $host
        }
        
        $performanceTest = @{
            HostName = $HostName
            VMName = $VMName
            DurationMinutes = $DurationMinutes
            SampleIntervalSeconds = $SampleIntervalSeconds
            Timestamp = Get-Date
            HostPerformance = @{}
            VMPerformance = @()
            Issues = @()
            Recommendations = @()
        }
        
        # Test host performance
        $hostCounters = @(
            "\Processor(_Total)\% Processor Time",
            "\Memory\Available MBytes",
            "\PhysicalDisk(_Total)\% Disk Time",
            "\Network Interface(*)\Bytes Total/sec"
        )
        
        $hostSamples = Get-Counter -Counter $hostCounters -MaxSamples 10 -SampleInterval $SampleIntervalSeconds -ErrorAction SilentlyContinue
        
        if ($hostSamples) {
            $hostPerformance = @{
                CPUUsage = ($hostSamples.CounterSamples | Where-Object { $_.Path -like "*Processor Time*" } | Measure-Object -Property CookedValue -Average).Average
                AvailableMemory = ($hostSamples.CounterSamples | Where-Object { $_.Path -like "*Available MBytes*" } | Measure-Object -Property CookedValue -Average).Average
                DiskUsage = ($hostSamples.CounterSamples | Where-Object { $_.Path -like "*Disk Time*" } | Measure-Object -Property CookedValue -Average).Average
                NetworkUsage = ($hostSamples.CounterSamples | Where-Object { $_.Path -like "*Bytes Total/sec*" } | Measure-Object -Property CookedValue -Average).Average
            }
            
            $performanceTest.HostPerformance = $hostPerformance
            
            # Check for host performance issues
            if ($hostPerformance.CPUUsage -gt 80) {
                $performanceTest.Issues += "High CPU usage on host: $($hostPerformance.CPUUsage)%"
                $performanceTest.Recommendations += "Consider adding more processors or migrating VMs"
            }
            
            if ($hostPerformance.AvailableMemory -lt 1024) {
                $performanceTest.Issues += "Low available memory on host: $($hostPerformance.AvailableMemory) MB"
                $performanceTest.Recommendations += "Consider adding more RAM or optimizing VM memory allocation"
            }
            
            if ($hostPerformance.DiskUsage -gt 80) {
                $performanceTest.Issues += "High disk usage on host: $($hostPerformance.DiskUsage)%"
                $performanceTest.Recommendations += "Consider adding more storage or optimizing disk usage"
            }
        }
        
        # Test VM performance
        foreach ($vm in $vms) {
            $vmPerformance = @{
                VMName = $vm.Name
                State = $vm.State
                Performance = @{}
            }
            
            if ($vm.State -eq "Running") {
                $vmCounters = @(
                    "\Hyper-V Hypervisor Logical Processor(_Total)\% Total Run Time",
                    "\Hyper-V Dynamic Memory VM($($vm.Name))\Available Memory",
                    "\Hyper-V Dynamic Memory VM($($vm.Name))\Guest Visible Physical Memory"
                )
                
                $vmSamples = Get-Counter -Counter $vmCounters -MaxSamples 10 -SampleInterval $SampleIntervalSeconds -ErrorAction SilentlyContinue
                
                if ($vmSamples) {
                    $vmPerformance.Performance = @{
                        CPUTotalRunTime = ($vmSamples.CounterSamples | Where-Object { $_.Path -like "*Logical Processor*" } | Measure-Object -Property CookedValue -Average).Average
                        AvailableMemory = ($vmSamples.CounterSamples | Where-Object { $_.Path -like "*Available Memory*" } | Measure-Object -Property CookedValue -Average).Average
                        GuestVisibleMemory = ($vmSamples.CounterSamples | Where-Object { $_.Path -like "*Guest Visible Physical Memory*" } | Measure-Object -Property CookedValue -Average).Average
                    }
                    
                    # Check for VM performance issues
                    if ($vmPerformance.Performance.CPUTotalRunTime -gt 90) {
                        $performanceTest.Issues += "High CPU usage on VM $($vm.Name): $($vmPerformance.Performance.CPUTotalRunTime)%"
                        $performanceTest.Recommendations += "Consider adding more processors to VM $($vm.Name)"
                    }
                    
                    if ($vmPerformance.Performance.AvailableMemory -lt 512) {
                        $performanceTest.Issues += "Low available memory on VM $($vm.Name): $($vmPerformance.Performance.AvailableMemory) MB"
                        $performanceTest.Recommendations += "Consider adding more memory to VM $($vm.Name)"
                    }
                }
            }
            
            $performanceTest.VMPerformance += $vmPerformance
        }
        
        Write-Verbose "Performance test completed"
        return $performanceTest
    }
    catch {
        Write-Error "Failed to test performance: $($_.Exception.Message)"
        throw
    }
}

# Migration Troubleshooting Functions

function Test-HyperVMigration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationHost,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Live", "Storage", "Quick")]
        [string]$MigrationType = "Live",
        
        [Parameter(Mandatory = $false)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    try {
        Write-Verbose "Testing migration compatibility for VM: $VMName to host: $DestinationHost"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $sourceHost = $vm.VMHost
        
        $migrationTest = @{
            VMName = $VMName
            SourceHost = $sourceHost.Name
            DestinationHost = $DestinationHost
            MigrationType = $MigrationType
            Timestamp = Get-Date
            Compatibility = "Compatible"
            Issues = @()
            Recommendations = @()
            DetailedResults = @{}
        }
        
        # Test basic connectivity
        try {
            $destinationHostObj = Get-VMHost -ComputerName $DestinationHost -ErrorAction Stop
            $migrationTest.DetailedResults.DestinationHostReachable = $true
        }
        catch {
            $migrationTest.Compatibility = "Incompatible"
            $migrationTest.Issues += "Cannot reach destination host: $DestinationHost"
            $migrationTest.DetailedResults.DestinationHostReachable = $false
        }
        
        # Test VM state
        if ($vm.State -ne "Running" -and $MigrationType -eq "Live") {
            $migrationTest.Compatibility = "Incompatible"
            $migrationTest.Issues += "VM must be running for live migration"
            $migrationTest.Recommendations += "Start the VM before attempting live migration"
        }
        
        # Test VM generation compatibility
        if ($vm.Generation -eq 1) {
            $migrationTest.Issues += "Generation 1 VMs may have compatibility issues"
            $migrationTest.Recommendations += "Consider upgrading to Generation 2 VM"
        }
        
        # Test storage compatibility
        if ($MigrationType -eq "Storage") {
            if (-not $DestinationPath) {
                $migrationTest.Compatibility = "Incompatible"
                $migrationTest.Issues += "Destination path is required for storage migration"
            } else {
                try {
                    $destinationPathObj = Get-Item -Path $DestinationPath -ErrorAction Stop
                    $migrationTest.DetailedResults.DestinationPathAccessible = $true
                }
                catch {
                    $migrationTest.Compatibility = "Incompatible"
                    $migrationTest.Issues += "Cannot access destination path: $DestinationPath"
                    $migrationTest.DetailedResults.DestinationPathAccessible = $false
                }
            }
        }
        
        # Test network compatibility
        $networkAdapters = Get-VMNetworkAdapter -VM $vm
        foreach ($adapter in $networkAdapters) {
            if (-not $adapter.SwitchName) {
                $migrationTest.Issues += "Network adapter $($adapter.Name) is not connected to a switch"
                $migrationTest.Recommendations += "Connect network adapter to a switch before migration"
            }
        }
        
        # Test integration services
        $integrationServices = Get-VMIntegrationService -VM $vm
        $disabledServices = $integrationServices | Where-Object { -not $_.Enabled }
        if ($disabledServices.Count -gt 0) {
            $migrationTest.Issues += "Some integration services are disabled"
            $migrationTest.Recommendations += "Enable integration services for better migration compatibility"
        }
        
        # Test VM size
        if ($vm.MemoryAssigned -gt 1TB) {
            $migrationTest.Issues += "Large memory VMs may have migration issues"
            $migrationTest.Recommendations += "Consider using storage migration for large memory VMs"
        }
        
        Write-Verbose "Migration compatibility test completed for VM: $VMName"
        return $migrationTest
    }
    catch {
        Write-Error "Failed to test migration compatibility: $($_.Exception.Message)"
        throw
    }
}

# Recovery Operations Functions

function Repair-HyperVIssues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "Automatic", "Interactive")]
        [string]$RepairMode = "Automatic",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeVMs,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeHost,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeStorage,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetwork
    )
    
    try {
        Write-Verbose "Repairing Hyper-V issues"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        $repairResults = @{
            HostName = $HostName
            VMName = $VMName
            RepairMode = $RepairMode
            Timestamp = Get-Date
            IssuesRepaired = 0
            IssuesFailed = 0
            RepairedIssues = @()
            FailedIssues = @()
            Recommendations = @()
        }
        
        # Repair host issues
        if ($IncludeHost) {
            # Check host state
            if ($host.State -ne "Enabled") {
                try {
                    Enable-VMHost -VMHost $host
                    $repairResults.IssuesRepaired++
                    $repairResults.RepairedIssues += "Host state restored to enabled"
                }
                catch {
                    $repairResults.IssuesFailed++
                    $repairResults.FailedIssues += "Failed to restore host state: $($_.Exception.Message)"
                }
            }
            
            # Check host services
            $services = @("vmms", "vmcompute", "vmwp")
            foreach ($service in $services) {
                $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($serviceObj -and $serviceObj.Status -ne "Running") {
                    try {
                        Start-Service -Name $service
                        $repairResults.IssuesRepaired++
                        $repairResults.RepairedIssues += "Service $service started"
                    }
                    catch {
                        $repairResults.IssuesFailed++
                        $repairResults.FailedIssues += "Failed to start service $service`: $($_.Exception.Message)"
                    }
                }
            }
        }
        
        # Repair VM issues
        if ($IncludeVMs) {
            $vms = if ($VMName) { @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop) } else { Get-VM -VMHost $host }
            
            foreach ($vm in $vms) {
                # Repair VM state issues
                if ($vm.State -eq "Paused") {
                    try {
                        Resume-VM -VM $vm
                        $repairResults.IssuesRepaired++
                        $repairResults.RepairedIssues += "VM $($vm.Name) resumed from paused state"
                    }
                    catch {
                        $repairResults.IssuesFailed++
                        $repairResults.FailedIssues += "Failed to resume VM $($vm.Name)`: $($_.Exception.Message)"
                    }
                }
                
                # Repair integration services
                $integrationServices = Get-VMIntegrationService -VM $vm
                $disabledServices = $integrationServices | Where-Object { -not $_.Enabled }
                foreach ($service in $disabledServices) {
                    try {
                        Enable-VMIntegrationService -VM $vm -Name $service.Name
                        $repairResults.IssuesRepaired++
                        $repairResults.RepairedIssues += "Integration service $($service.Name) enabled for VM $($vm.Name)"
                    }
                    catch {
                        $repairResults.IssuesFailed++
                        $repairResults.FailedIssues += "Failed to enable integration service $($service.Name) for VM $($vm.Name)`: $($_.Exception.Message)"
                    }
                }
                
                # Repair network adapter issues
                $networkAdapters = Get-VMNetworkAdapter -VM $vm
                foreach ($adapter in $networkAdapters) {
                    if (-not $adapter.SwitchName) {
                        try {
                            Set-VMNetworkAdapter -VMNetworkAdapter $adapter -SwitchName "Default Switch"
                            $repairResults.IssuesRepaired++
                            $repairResults.RepairedIssues += "Network adapter $($adapter.Name) connected to Default Switch for VM $($vm.Name)"
                        }
                        catch {
                            $repairResults.IssuesFailed++
                            $repairResults.FailedIssues += "Failed to connect network adapter $($adapter.Name) for VM $($vm.Name)`: $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
        
        # Repair storage issues
        if ($IncludeStorage) {
            $vms = if ($VMName) { @(Get-VM -Name $VMName -VMHost $host -ErrorAction Stop) } else { Get-VM -VMHost $host }
            
            foreach ($vm in $vms) {
                $hardDrives = Get-VMHardDiskDrive -VM $vm
                foreach ($drive in $hardDrives) {
                    if (Test-Path $drive.Path) {
                        try {
                            # Check VHD integrity
                            $vhdInfo = Get-VHD -Path $drive.Path -ErrorAction SilentlyContinue
                            if ($vhdInfo) {
                                # Optimize VHD if needed
                                if ($vhdInfo.FileSize -gt ($vhdInfo.Size * 0.8)) {
                                    Optimize-VHD -Path $drive.Path -Mode Full
                                    $repairResults.IssuesRepaired++
                                    $repairResults.RepairedIssues += "VHD $($drive.Path) optimized for VM $($vm.Name)"
                                }
                            }
                        }
                        catch {
                            $repairResults.IssuesFailed++
                            $repairResults.FailedIssues += "Failed to optimize VHD $($drive.Path) for VM $($vm.Name)`: $($_.Exception.Message)"
                        }
                    }
                }
            }
        }
        
        # Generate recommendations
        if ($repairResults.IssuesFailed -gt 0) {
            $repairResults.Recommendations += "Some issues could not be automatically repaired. Manual intervention may be required."
        }
        
        if ($repairResults.IssuesRepaired -gt 0) {
            $repairResults.Recommendations += "Issues have been repaired. Monitor the system for stability."
        }
        
        Write-Verbose "Hyper-V repair operations completed"
        return $repairResults
    }
    catch {
        Write-Error "Failed to repair Hyper-V issues: $($_.Exception.Message)"
        throw
    }
}

# Health Check Functions

function Test-HyperVHealth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Standard", "Comprehensive")]
        [string]$HealthLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformance,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeStorage,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetwork,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSecurity
    )
    
    try {
        Write-Verbose "Running Hyper-V health check"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        $healthCheck = @{
            HostName = $HostName
            VMName = $VMName
            HealthLevel = $HealthLevel
            Timestamp = Get-Date
            OverallHealth = "Healthy"
            HostHealth = @{}
            VMHealth = @()
            Issues = @()
            Recommendations = @()
        }
        
        # Check host health
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
            $healthCheck.Issues += "Host is not in enabled state"
            $healthCheck.OverallHealth = "Critical"
        }
        
        if ($host.FreeMemory -lt ($host.TotalMemory * 0.1)) {
            $healthCheck.Issues += "Low memory on host"
            $healthCheck.OverallHealth = "Warning"
        }
        
        $healthCheck.HostHealth = $hostHealth
        
        # Check VM health
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
                $healthCheck.Issues += "VM $($vm.Name) is in $($vm.State) state"
                $healthCheck.OverallHealth = "Warning"
            }
            
            $healthCheck.VMHealth += $vmHealth
        }
        
        # Determine overall health
        if ($healthCheck.Issues.Count -gt 0) {
            $criticalIssues = $healthCheck.Issues | Where-Object { $_ -like "*Critical*" -or $_ -like "*Failed*" }
            if ($criticalIssues.Count -gt 0) {
                $healthCheck.OverallHealth = "Critical"
            }
        }
        
        # Generate recommendations
        if ($healthCheck.OverallHealth -eq "Critical") {
            $healthCheck.Recommendations += "Immediate attention required for critical issues"
        } elseif ($healthCheck.OverallHealth -eq "Warning") {
            $healthCheck.Recommendations += "Monitor warning issues and consider proactive measures"
        } else {
            $healthCheck.Recommendations += "System is healthy. Continue regular monitoring"
        }
        
        Write-Verbose "Hyper-V health check completed"
        return $healthCheck
    }
    catch {
        Write-Error "Failed to run health check: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Test-HyperVMDiagnostics',
    'Analyze-HyperVEventLogs',
    'Test-HyperVPerformance',
    'Test-HyperVMigration',
    'Repair-HyperVIssues',
    'Test-HyperVHealth'
)
