#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Resource Manager (FSRM) Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive File Server Resource Manager capabilities
    including quota management, file screening, and storage reporting.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-FSRMPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for FSRM operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        FSRMInstalled = $false
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
    }
    
    # Check if FSRM feature is installed
    try {
        $feature = Get-WindowsFeature -Name "FS-Resource-Manager" -ErrorAction SilentlyContinue
        $prerequisites.FSRMInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check FSRM installation: $($_.Exception.Message)"
    }
    
    # Check if FSRM PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name FileServerResourceManager -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check FSRM PowerShell module: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function New-FSRMQuota {
    <#
    .SYNOPSIS
        Creates a new FSRM quota
    
    .DESCRIPTION
        This function creates a new File Server Resource Manager quota
        with specified limits and notification settings.
    
    .PARAMETER Path
        Path to apply the quota to
    
    .PARAMETER QuotaName
        Name for the quota template
    
    .PARAMETER SizeLimit
        Size limit for the quota (e.g., "100GB", "1TB")
    
    .PARAMETER QuotaType
        Type of quota (Hard, Soft)
    
    .PARAMETER NotificationThresholds
        Array of threshold percentages for notifications
    
    .PARAMETER EmailNotifications
        Email addresses for notifications
    
    .PARAMETER EventLogNotifications
        Enable event log notifications
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-FSRMQuota -Path "D:\Shares\Users" -QuotaName "UserQuota" -SizeLimit "5GB" -QuotaType "Hard"
    
    .EXAMPLE
        New-FSRMQuota -Path "D:\Shares\Projects" -QuotaName "ProjectQuota" -SizeLimit "50GB" -QuotaType "Soft" -NotificationThresholds @(80, 90, 95)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$QuotaName,
        
        [Parameter(Mandatory = $true)]
        [string]$SizeLimit,
        
        [ValidateSet("Hard", "Soft")]
        [string]$QuotaType = "Hard",
        
        [int[]]$NotificationThresholds = @(80, 90, 95),
        
        [string[]]$EmailNotifications,
        
        [switch]$EventLogNotifications
    )
    
    try {
        Write-Verbose "Creating FSRM quota: $QuotaName for path: $Path"
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.FSRMInstalled) {
            throw "File Server Resource Manager feature is not installed. Please install it first."
        }
        
        $quotaResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Path = $Path
            QuotaName = $QuotaName
            SizeLimit = $SizeLimit
            QuotaType = $QuotaType
            Success = $false
            Error = $null
            QuotaObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create quota template first
            $templateParams = @{
                Name = $QuotaName
                Size = $SizeLimit
                Threshold = $NotificationThresholds
            }
            
            if ($EmailNotifications) {
                $templateParams.Add("MailTo", $EmailNotifications)
            }
            
            if ($EventLogNotifications) {
                $templateParams.Add("EventLog", $true)
            }
            
            # Create quota template
            New-FsrmQuotaTemplate @templateParams -ErrorAction Stop | Out-Null
            
            # Apply quota to path
            $quota = New-FsrmQuota -Path $Path -Template $QuotaName -ErrorAction Stop
            
            $quotaResult.QuotaObject = $quota
            $quotaResult.Success = $true
            
            Write-Verbose "FSRM quota created successfully: $QuotaName"
            
        } catch {
            $quotaResult.Error = $_.Exception.Message
            Write-Warning "Failed to create FSRM quota: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$quotaResult
        
    } catch {
        Write-Error "Error creating FSRM quota: $($_.Exception.Message)"
        return $null
    }
}

function Get-FSRMQuotaStatus {
    <#
    .SYNOPSIS
        Gets FSRM quota status for specified paths
    
    .DESCRIPTION
        This function retrieves comprehensive quota status information
        including usage, limits, and violation status.
    
    .PARAMETER Paths
        Array of paths to get quota status for (optional, defaults to all)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-FSRMQuotaStatus
    
    .EXAMPLE
        Get-FSRMQuotaStatus -Paths @("D:\Shares\Users", "D:\Shares\Projects")
    #>
    [CmdletBinding()]
    param(
        [string[]]$Paths
    )
    
    try {
        Write-Verbose "Getting FSRM quota status..."
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.FSRMInstalled) {
            throw "File Server Resource Manager feature is not installed."
        }
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Paths = $Paths
            QuotaStatus = @()
            Summary = @{}
            Prerequisites = $prerequisites
        }
        
        # Get quotas
        $quotas = Get-FsrmQuota -ErrorAction SilentlyContinue
        
        if ($Paths) {
            $quotas = $quotas | Where-Object { $Paths -contains $_.Path }
        }
        
        foreach ($quota in $quotas) {
            $statusInfo = @{
                Path = $quota.Path
                QuotaName = $quota.Name
                SizeLimit = $quota.Size
                SizeUsed = $quota.SizeUsed
                UsagePercent = if ($quota.Size -gt 0) { [math]::Round(($quota.SizeUsed / $quota.Size) * 100, 2) } else { 0 }
                QuotaType = $quota.QuotaType
                Status = $quota.Status
                Template = $quota.Template
                LastNotificationTime = $quota.LastNotificationTime
                LastWarningTime = $quota.LastWarningTime
                LastThresholdTime = $quota.LastThresholdTime
            }
            
            $statusResults.QuotaStatus += [PSCustomObject]$statusInfo
        }
        
        # Generate summary
        $totalQuotas = $statusResults.QuotaStatus.Count
        $violatedQuotas = ($statusResults.QuotaStatus | Where-Object { $_.Status -eq "Violated" }).Count
        $warningQuotas = ($statusResults.QuotaStatus | Where-Object { $_.UsagePercent -ge 80 -and $_.UsagePercent -lt 100 }).Count
        $totalUsedSpace = ($statusResults.QuotaStatus | Measure-Object -Property SizeUsed -Sum).Sum
        $totalLimitSpace = ($statusResults.QuotaStatus | Measure-Object -Property SizeLimit -Sum).Sum
        
        $statusResults.Summary = @{
            TotalQuotas = $totalQuotas
            ViolatedQuotas = $violatedQuotas
            WarningQuotas = $warningQuotas
            TotalUsedSpace = $totalUsedSpace
            TotalLimitSpace = $totalLimitSpace
            OverallUsagePercent = if ($totalLimitSpace -gt 0) { [math]::Round(($totalUsedSpace / $totalLimitSpace) * 100, 2) } else { 0 }
        }
        
        Write-Verbose "FSRM quota status retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting FSRM quota status: $($_.Exception.Message)"
        return $null
    }
}

function New-FSRMFileScreen {
    <#
    .SYNOPSIS
        Creates a new FSRM file screen
    
    .DESCRIPTION
        This function creates a new File Server Resource Manager file screen
        to block or monitor specific file types.
    
    .PARAMETER Path
        Path to apply the file screen to
    
    .PARAMETER ScreenName
        Name for the file screen
    
    .PARAMETER FileGroups
        File groups to screen (e.g., "Executable Files", "Audio and Video Files")
    
    .PARAMETER ScreenType
        Type of screen (Active, Passive)
    
    .PARAMETER NotificationThresholds
        Array of threshold percentages for notifications
    
    .PARAMETER EmailNotifications
        Email addresses for notifications
    
    .PARAMETER EventLogNotifications
        Enable event log notifications
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-FSRMFileScreen -Path "D:\Shares\Public" -ScreenName "BlockExecutables" -FileGroups @("Executable Files") -ScreenType "Active"
    
    .EXAMPLE
        New-FSRMFileScreen -Path "D:\Shares\Media" -ScreenName "MonitorMedia" -FileGroups @("Audio and Video Files") -ScreenType "Passive"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$ScreenName,
        
        [Parameter(Mandatory = $true)]
        [string[]]$FileGroups,
        
        [ValidateSet("Active", "Passive")]
        [string]$ScreenType = "Active",
        
        [int[]]$NotificationThresholds = @(80, 90, 95),
        
        [string[]]$EmailNotifications,
        
        [switch]$EventLogNotifications
    )
    
    try {
        Write-Verbose "Creating FSRM file screen: $ScreenName for path: $Path"
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.FSRMInstalled) {
            throw "File Server Resource Manager feature is not installed. Please install it first."
        }
        
        $screenResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Path = $Path
            ScreenName = $ScreenName
            FileGroups = $FileGroups
            ScreenType = $ScreenType
            Success = $false
            Error = $null
            ScreenObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create file screen template first
            $templateParams = @{
                Name = $ScreenName
                IncludeGroup = $FileGroups
                Active = ($ScreenType -eq "Active")
                Threshold = $NotificationThresholds
            }
            
            if ($EmailNotifications) {
                $templateParams.Add("MailTo", $EmailNotifications)
            }
            
            if ($EventLogNotifications) {
                $templateParams.Add("EventLog", $true)
            }
            
            # Create file screen template
            New-FsrmFileScreenTemplate @templateParams -ErrorAction Stop | Out-Null
            
            # Apply file screen to path
            $fileScreen = New-FsrmFileScreen -Path $Path -Template $ScreenName -ErrorAction Stop
            
            $screenResult.ScreenObject = $fileScreen
            $screenResult.Success = $true
            
            Write-Verbose "FSRM file screen created successfully: $ScreenName"
            
        } catch {
            $screenResult.Error = $_.Exception.Message
            Write-Warning "Failed to create FSRM file screen: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$screenResult
        
    } catch {
        Write-Error "Error creating FSRM file screen: $($_.Exception.Message)"
        return $null
    }
}

function Get-FSRMFileScreenStatus {
    <#
    .SYNOPSIS
        Gets FSRM file screen status for specified paths
    
    .DESCRIPTION
        This function retrieves comprehensive file screen status information
        including violations, blocked files, and monitoring statistics.
    
    .PARAMETER Paths
        Array of paths to get file screen status for (optional, defaults to all)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-FSRMFileScreenStatus
    
    .EXAMPLE
        Get-FSRMFileScreenStatus -Paths @("D:\Shares\Public", "D:\Shares\Media")
    #>
    [CmdletBinding()]
    param(
        [string[]]$Paths
    )
    
    try {
        Write-Verbose "Getting FSRM file screen status..."
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.FSRMInstalled) {
            throw "File Server Resource Manager feature is not installed."
        }
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Paths = $Paths
            FileScreenStatus = @()
            Violations = @()
            Summary = @{}
            Prerequisites = $prerequisites
        }
        
        # Get file screens
        $fileScreens = Get-FsrmFileScreen -ErrorAction SilentlyContinue
        
        if ($Paths) {
            $fileScreens = $fileScreens | Where-Object { $Paths -contains $_.Path }
        }
        
        foreach ($fileScreen in $fileScreens) {
            $statusInfo = @{
                Path = $fileScreen.Path
                ScreenName = $fileScreen.Name
                Template = $fileScreen.Template
                Active = $fileScreen.Active
                IncludeGroup = $fileScreen.IncludeGroup
                LastNotificationTime = $fileScreen.LastNotificationTime
                LastWarningTime = $fileScreen.LastWarningTime
                LastThresholdTime = $fileScreen.LastThresholdTime
            }
            
            $statusResults.FileScreenStatus += [PSCustomObject]$statusInfo
        }
        
        # Get file screen violations
        $violations = Get-FsrmFileScreenViolation -ErrorAction SilentlyContinue
        
        if ($Paths) {
            $violations = $violations | Where-Object { $Paths -contains $_.Path }
        }
        
        foreach ($violation in $violations) {
            $violationInfo = @{
                Path = $violation.Path
                FileName = $violation.FileName
                FilePath = $violation.FilePath
                ViolationTime = $violation.ViolationTime
                ViolationType = $violation.ViolationType
                UserName = $violation.UserName
                ComputerName = $violation.ComputerName
            }
            
            $statusResults.Violations += [PSCustomObject]$violationInfo
        }
        
        # Generate summary
        $totalScreens = $statusResults.FileScreenStatus.Count
        $activeScreens = ($statusResults.FileScreenStatus | Where-Object { $_.Active }).Count
        $totalViolations = $statusResults.Violations.Count
        $recentViolations = ($statusResults.Violations | Where-Object { $_.ViolationTime -gt (Get-Date).AddDays(-7) }).Count
        
        $statusResults.Summary = @{
            TotalFileScreens = $totalScreens
            ActiveFileScreens = $activeScreens
            TotalViolations = $totalViolations
            RecentViolations = $recentViolations
        }
        
        Write-Verbose "FSRM file screen status retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting FSRM file screen status: $($_.Exception.Message)"
        return $null
    }
}

function New-FSRMStorageReport {
    <#
    .SYNOPSIS
        Creates a new FSRM storage report
    
    .DESCRIPTION
        This function creates and runs a File Server Resource Manager storage report
        to analyze disk usage and file distribution.
    
    .PARAMETER ReportName
        Name for the storage report
    
    .PARAMETER Paths
        Array of paths to include in the report
    
    .PARAMETER ReportTypes
        Types of reports to generate (DuplicateFiles, FileScreenAudit, LargeFiles, QuotaUsage, etc.)
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER EmailReport
        Email addresses to send the report to
    
    .PARAMETER ScheduleType
        Schedule for the report (Once, Daily, Weekly, Monthly)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-FSRMStorageReport -ReportName "WeeklyUsage" -Paths @("D:\Shares") -ReportTypes @("QuotaUsage", "LargeFiles")
    
    .EXAMPLE
        New-FSRMStorageReport -ReportName "MonthlyAudit" -Paths @("D:\Shares") -ReportTypes @("DuplicateFiles", "FileScreenAudit") -ScheduleType "Monthly"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportName,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Paths,
        
        [Parameter(Mandatory = $true)]
        [string[]]$ReportTypes,
        
        [string]$OutputPath,
        
        [string[]]$EmailReport,
        
        [ValidateSet("Once", "Daily", "Weekly", "Monthly")]
        [string]$ScheduleType = "Once"
    )
    
    try {
        Write-Verbose "Creating FSRM storage report: $ReportName"
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.FSRMInstalled) {
            throw "File Server Resource Manager feature is not installed. Please install it first."
        }
        
        $reportResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ReportName = $ReportName
            Paths = $Paths
            ReportTypes = $ReportTypes
            OutputPath = $OutputPath
            Success = $false
            Error = $null
            ReportJob = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create report parameters
            $reportParams = @{
                Name = $ReportName
                Namespace = $Paths
                ReportType = $ReportTypes
            }
            
            if ($OutputPath) {
                $reportParams.Add("Path", $OutputPath)
            }
            
            if ($EmailReport) {
                $reportParams.Add("MailTo", $EmailReport)
            }
            
            # Create and run report
            New-FsrmStorageReport @reportParams -ErrorAction Stop | Out-Null
            
            if ($ScheduleType -eq "Once") {
                # Run report immediately
                $reportJob = Start-FsrmStorageReport -Name $ReportName -ErrorAction Stop
                $reportResult.ReportJob = $reportJob
            } else {
                # Schedule report
                $scheduleDays = switch ($ScheduleType) {
                    "Daily" { @(0,1,2,3,4,5,6) }
                    "Weekly" { @(0) }
                    "Monthly" { @(0) }
                }
                
                Set-FsrmStorageReport -Name $ReportName -Schedule @{
                    Days = $scheduleDays
                    StartTime = "02:00"
                } -ErrorAction SilentlyContinue
            }
            
            $reportResult.Success = $true
            
            Write-Verbose "FSRM storage report created successfully: $ReportName"
            
        } catch {
            $reportResult.Error = $_.Exception.Message
            Write-Warning "Failed to create FSRM storage report: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$reportResult
        
    } catch {
        Write-Error "Error creating FSRM storage report: $($_.Exception.Message)"
        return $null
    }
}

function Get-FSRMStorageReports {
    <#
    .SYNOPSIS
        Gets FSRM storage report status and history
    
    .DESCRIPTION
        This function retrieves information about FSRM storage reports
        including status, history, and available reports.
    
    .PARAMETER ReportName
        Specific report name to get status for (optional)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-FSRMStorageReports
    
    .EXAMPLE
        Get-FSRMStorageReports -ReportName "WeeklyUsage"
    #>
    [CmdletBinding()]
    param(
        [string]$ReportName
    )
    
    try {
        Write-Verbose "Getting FSRM storage report status..."
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.FSRMInstalled) {
            throw "File Server Resource Manager feature is not installed."
        }
        
        $reportResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ReportName = $ReportName
            Reports = @()
            ReportJobs = @()
            Summary = @{}
            Prerequisites = $prerequisites
        }
        
        # Get storage reports
        $reports = Get-FsrmStorageReport -ErrorAction SilentlyContinue
        
        if ($ReportName) {
            $reports = $reports | Where-Object { $_.Name -eq $ReportName }
        }
        
        foreach ($report in $reports) {
            $reportInfo = @{
                Name = $report.Name
                Namespace = $report.Namespace
                ReportType = $report.ReportType
                Path = $report.Path
                MailTo = $report.MailTo
                Schedule = $report.Schedule
                LastRunTime = $report.LastRunTime
                LastReportTime = $report.LastReportTime
            }
            
            $reportResults.Reports += [PSCustomObject]$reportInfo
        }
        
        # Get report jobs
        $reportJobs = Get-FsrmStorageReportJob -ErrorAction SilentlyContinue
        
        if ($ReportName) {
            $reportJobs = $reportJobs | Where-Object { $_.Name -eq $ReportName }
        }
        
        foreach ($job in $reportJobs) {
            $jobInfo = @{
                Name = $job.Name
                Status = $job.Status
                StartTime = $job.StartTime
                EndTime = $job.EndTime
                Duration = if ($job.EndTime) { $job.EndTime - $job.StartTime } else { (Get-Date) - $job.StartTime }
                ErrorMessage = $job.ErrorMessage
            }
            
            $reportResults.ReportJobs += [PSCustomObject]$jobInfo
        }
        
        # Generate summary
        $totalReports = $reportResults.Reports.Count
        $runningJobs = ($reportResults.ReportJobs | Where-Object { $_.Status -eq "Running" }).Count
        $completedJobs = ($reportResults.ReportJobs | Where-Object { $_.Status -eq "Completed" }).Count
        $failedJobs = ($reportResults.ReportJobs | Where-Object { $_.Status -eq "Failed" }).Count
        
        $reportResults.Summary = @{
            TotalReports = $totalReports
            RunningJobs = $runningJobs
            CompletedJobs = $completedJobs
            FailedJobs = $failedJobs
        }
        
        Write-Verbose "FSRM storage report status retrieved successfully"
        return [PSCustomObject]$reportResults
        
    } catch {
        Write-Error "Error getting FSRM storage report status: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'New-FSRMQuota',
    'Get-FSRMQuotaStatus',
    'New-FSRMFileScreen',
    'Get-FSRMFileScreenStatus',
    'New-FSRMStorageReport',
    'Get-FSRMStorageReports'
)

# Module initialization
Write-Verbose "BackupStorage-FSRM module loaded successfully. Version: $ModuleVersion"
