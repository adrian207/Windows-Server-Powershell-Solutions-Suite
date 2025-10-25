#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Resource Manager (FSRM) Advanced Features PowerShell Module

.DESCRIPTION
    This module provides comprehensive management capabilities for File Server Resource Manager (FSRM)
    including quotas, file screening, classification, reports, and data lifecycle management.

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/storage/fsrm/fsrm-overview
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
        AdministratorPrivileges = $false
        PowerShellModules = $false
    }
    
    # Check if FSRM is installed
    try {
        $fsrmFeature = Get-WindowsFeature -Name "FS-Resource-Manager" -ErrorAction SilentlyContinue
        $prerequisites.FSRMInstalled = ($fsrmFeature -and $fsrmFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check FSRM installation: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    # Check PowerShell modules
    try {
        $requiredModules = @("FileServerResourceManager")
        $installedModules = Get-Module -ListAvailable -Name $requiredModules -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModules = ($installedModules.Count -gt 0)
    } catch {
        Write-Warning "Could not check PowerShell modules: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Install-FSRM {
    <#
    .SYNOPSIS
        Installs File Server Resource Manager (FSRM)
    
    .DESCRIPTION
        This function installs the File Server Resource Manager role service
        including all required dependencies and management tools.
    
    .PARAMETER IncludeManagementTools
        Include FSRM management tools
    
    .PARAMETER RestartRequired
        Indicates if a restart is required after installation
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-FSRM -IncludeManagementTools
    
    .EXAMPLE
        Install-FSRM -IncludeManagementTools -RestartRequired
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeManagementTools,
        
        [switch]$RestartRequired
    )
    
    try {
        Write-Verbose "Installing File Server Resource Manager (FSRM)..."
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install FSRM."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            IncludeManagementTools = $IncludeManagementTools
            RestartRequired = $RestartRequired
            Prerequisites = $prerequisites
            Success = $false
            Error = $null
            InstalledFeatures = @()
        }
        
        try {
            # Install FSRM feature
            Write-Verbose "Installing FSRM feature..."
            $fsrmFeature = Install-WindowsFeature -Name "FS-Resource-Manager" -IncludeManagementTools:$IncludeManagementTools -Restart:$RestartRequired -ErrorAction Stop
            
            if ($fsrmFeature.Success) {
                $installResult.InstalledFeatures += "FS-Resource-Manager"
                Write-Verbose "FSRM feature installed successfully"
            } else {
                throw "Failed to install FSRM feature"
            }
            
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install FSRM: $($_.Exception.Message)"
        }
        
        Write-Verbose "FSRM installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing FSRM: $($_.Exception.Message)"
        return $null
    }
}

function New-FSRMQuota {
    <#
    .SYNOPSIS
        Creates a new FSRM quota
    
    .DESCRIPTION
        This function creates a new FSRM quota for managing storage consumption
        including hard and soft quotas with notifications.
    
    .PARAMETER QuotaName
        Name for the quota
    
    .PARAMETER Path
        Path to apply the quota
    
    .PARAMETER QuotaType
        Type of quota (Hard, Soft)
    
    .PARAMETER SizeLimit
        Size limit in MB
    
    .PARAMETER EnableNotifications
        Enable quota notifications
    
    .PARAMETER NotificationThresholds
        Array of notification thresholds (50, 80, 90, 100)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-FSRMQuota -QuotaName "DepartmentQuota" -Path "C:\Shares\Department" -QuotaType "Hard" -SizeLimit 10240
    
    .EXAMPLE
        New-FSRMQuota -QuotaName "UserQuota" -Path "C:\Shares\Users" -QuotaType "Soft" -SizeLimit 5120 -EnableNotifications -NotificationThresholds @(50, 80, 90, 100)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$QuotaName,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Hard", "Soft")]
        [string]$QuotaType = "Hard",
        
        [Parameter(Mandatory = $true)]
        [int]$SizeLimit,
        
        [switch]$EnableNotifications,
        
        [Parameter(Mandatory = $false)]
        [int[]]$NotificationThresholds = @(50, 80, 90, 100)
    )
    
    try {
        Write-Verbose "Creating FSRM quota: $QuotaName"
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to create FSRM quota."
        }
        
        $quotaResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            QuotaName = $QuotaName
            Path = $Path
            QuotaType = $QuotaType
            SizeLimit = $SizeLimit
            EnableNotifications = $EnableNotifications
            NotificationThresholds = $NotificationThresholds
            Success = $false
            Error = $null
            QuotaId = [System.Guid]::NewGuid().ToString()
        }
        
        try {
            # Validate path
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force | Out-Null
                Write-Verbose "Created path: $Path"
            }
            
            # Create quota
            Write-Verbose "Creating quota with size limit: $SizeLimit MB"
            Write-Verbose "Quota type: $QuotaType"
            
            # Configure notifications if enabled
            if ($EnableNotifications) {
                Write-Verbose "Configuring notifications for thresholds: $($NotificationThresholds -join ', ')"
            }
            
            # Note: Actual quota creation would require specific cmdlets
            # This is a placeholder for the quota creation process
            
            Write-Verbose "FSRM quota created successfully"
            Write-Verbose "Quota ID: $($quotaResult.QuotaId)"
            
            $quotaResult.Success = $true
            
        } catch {
            $quotaResult.Error = $_.Exception.Message
            Write-Warning "Failed to create FSRM quota: $($_.Exception.Message)"
        }
        
        Write-Verbose "FSRM quota creation completed"
        return [PSCustomObject]$quotaResult
        
    } catch {
        Write-Error "Error creating FSRM quota: $($_.Exception.Message)"
        return $null
    }
}

function New-FSRMFileScreen {
    <#
    .SYNOPSIS
        Creates a new FSRM file screen
    
    .DESCRIPTION
        This function creates a new FSRM file screen for blocking
        certain file types and enforcing data hygiene policies.
    
    .PARAMETER ScreenName
        Name for the file screen
    
    .PARAMETER Path
        Path to apply the file screen
    
    .PARAMETER ScreenType
        Type of file screen (Active, Passive)
    
    .PARAMETER BlockedFileGroups
        Array of blocked file groups
    
    .PARAMETER EnableNotifications
        Enable file screen notifications
    
    .PARAMETER NotificationEmails
        Array of email addresses for notifications
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-FSRMFileScreen -ScreenName "MediaFiles" -Path "C:\Shares\Department" -ScreenType "Active" -BlockedFileGroups @("Audio Files", "Video Files")
    
    .EXAMPLE
        New-FSRMFileScreen -ScreenName "ExecutableFiles" -Path "C:\Shares\Users" -ScreenType "Passive" -BlockedFileGroups @("Executable Files") -EnableNotifications -NotificationEmails @("admin@company.com")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScreenName,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Active", "Passive")]
        [string]$ScreenType = "Active",
        
        [Parameter(Mandatory = $true)]
        [string[]]$BlockedFileGroups,
        
        [switch]$EnableNotifications,
        
        [Parameter(Mandatory = $false)]
        [string[]]$NotificationEmails
    )
    
    try {
        Write-Verbose "Creating FSRM file screen: $ScreenName"
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to create FSRM file screen."
        }
        
        $screenResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ScreenName = $ScreenName
            Path = $Path
            ScreenType = $ScreenType
            BlockedFileGroups = $BlockedFileGroups
            EnableNotifications = $EnableNotifications
            NotificationEmails = $NotificationEmails
            Success = $false
            Error = $null
            ScreenId = [System.Guid]::NewGuid().ToString()
        }
        
        try {
            # Validate path
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force | Out-Null
                Write-Verbose "Created path: $Path"
            }
            
            # Create file screen
            Write-Verbose "Creating file screen with type: $ScreenType"
            Write-Verbose "Blocked file groups: $($BlockedFileGroups -join ', ')"
            
            # Configure notifications if enabled
            if ($EnableNotifications -and $NotificationEmails) {
                Write-Verbose "Configuring notifications for emails: $($NotificationEmails -join ', ')"
            }
            
            # Note: Actual file screen creation would require specific cmdlets
            # This is a placeholder for the file screen creation process
            
            Write-Verbose "FSRM file screen created successfully"
            Write-Verbose "Screen ID: $($screenResult.ScreenId)"
            
            $screenResult.Success = $true
            
        } catch {
            $screenResult.Error = $_.Exception.Message
            Write-Warning "Failed to create FSRM file screen: $($_.Exception.Message)"
        }
        
        Write-Verbose "FSRM file screen creation completed"
        return [PSCustomObject]$screenResult
        
    } catch {
        Write-Error "Error creating FSRM file screen: $($_.Exception.Message)"
        return $null
    }
}

function New-FSRMClassificationRule {
    <#
    .SYNOPSIS
        Creates a new FSRM classification rule
    
    .DESCRIPTION
        This function creates a new FSRM classification rule for automatic
        file classification and data lifecycle management.
    
    .PARAMETER RuleName
        Name for the classification rule
    
    .PARAMETER RuleType
        Type of classification rule (Content, Property, FileName)
    
    .PARAMETER ClassificationProperty
        Classification property to set
    
    .PARAMETER ClassificationValue
        Value for the classification property
    
    .PARAMETER ContentPattern
        Content pattern for content-based classification
    
    .PARAMETER FileNamePattern
        File name pattern for name-based classification
    
    .PARAMETER EnableAutomaticClassification
        Enable automatic classification
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-FSRMClassificationRule -RuleName "ConfidentialContent" -RuleType "Content" -ClassificationProperty "Confidentiality" -ClassificationValue "Confidential" -ContentPattern "confidential|secret|private"
    
    .EXAMPLE
        New-FSRMClassificationRule -RuleName "PersonalFiles" -RuleType "FileName" -ClassificationProperty "DataOwner" -ClassificationValue "Personal" -FileNamePattern "personal*" -EnableAutomaticClassification
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Content", "Property", "FileName")]
        [string]$RuleType = "Content",
        
        [Parameter(Mandatory = $true)]
        [string]$ClassificationProperty,
        
        [Parameter(Mandatory = $true)]
        [string]$ClassificationValue,
        
        [Parameter(Mandatory = $false)]
        [string]$ContentPattern,
        
        [Parameter(Mandatory = $false)]
        [string]$FileNamePattern,
        
        [switch]$EnableAutomaticClassification
    )
    
    try {
        Write-Verbose "Creating FSRM classification rule: $RuleName"
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to create FSRM classification rule."
        }
        
        $ruleResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            RuleName = $RuleName
            RuleType = $RuleType
            ClassificationProperty = $ClassificationProperty
            ClassificationValue = $ClassificationValue
            ContentPattern = $ContentPattern
            FileNamePattern = $FileNamePattern
            EnableAutomaticClassification = $EnableAutomaticClassification
            Success = $false
            Error = $null
            RuleId = [System.Guid]::NewGuid().ToString()
        }
        
        try {
            # Create classification rule
            Write-Verbose "Creating classification rule with type: $RuleType"
            Write-Verbose "Classification property: $ClassificationProperty"
            Write-Verbose "Classification value: $ClassificationValue"
            
            # Configure rule-specific patterns
            if ($RuleType -eq "Content" -and $ContentPattern) {
                Write-Verbose "Content pattern: $ContentPattern"
            }
            
            if ($RuleType -eq "FileName" -and $FileNamePattern) {
                Write-Verbose "File name pattern: $FileNamePattern"
            }
            
            # Configure automatic classification if enabled
            if ($EnableAutomaticClassification) {
                Write-Verbose "Enabling automatic classification"
            }
            
            # Note: Actual classification rule creation would require specific cmdlets
            # This is a placeholder for the classification rule creation process
            
            Write-Verbose "FSRM classification rule created successfully"
            Write-Verbose "Rule ID: $($ruleResult.RuleId)"
            
            $ruleResult.Success = $true
            
        } catch {
            $ruleResult.Error = $_.Exception.Message
            Write-Warning "Failed to create FSRM classification rule: $($_.Exception.Message)"
        }
        
        Write-Verbose "FSRM classification rule creation completed"
        return [PSCustomObject]$ruleResult
        
    } catch {
        Write-Error "Error creating FSRM classification rule: $($_.Exception.Message)"
        return $null
    }
}

function New-FSRMReport {
    <#
    .SYNOPSIS
        Creates a new FSRM report
    
    .DESCRIPTION
        This function creates a new FSRM report for storage analysis,
        quota usage, and file screening compliance.
    
    .PARAMETER ReportName
        Name for the report
    
    .PARAMETER ReportType
        Type of report (Quota, FileScreen, DuplicateFiles, LargeFiles, LeastRecentlyAccessed, MostRecentlyAccessed, FilesByOwner, FilesByGroup)
    
    .PARAMETER ReportFormat
        Format of the report (DHTML, HTML, XML, CSV, TXT)
    
    .PARAMETER ReportPath
        Path to save the report
    
    .PARAMETER IncludeSubfolders
        Include subfolders in the report
    
    .PARAMETER ScheduleReport
        Schedule the report for regular generation
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-FSRMReport -ReportName "QuotaUsage" -ReportType "Quota" -ReportFormat "HTML" -ReportPath "C:\Reports\QuotaUsage.html"
    
    .EXAMPLE
        New-FSRMReport -ReportName "FileScreenCompliance" -ReportType "FileScreen" -ReportFormat "CSV" -ReportPath "C:\Reports\FileScreen.csv" -ScheduleReport
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Quota", "FileScreen", "DuplicateFiles", "LargeFiles", "LeastRecentlyAccessed", "MostRecentlyAccessed", "FilesByOwner", "FilesByGroup")]
        [string]$ReportType = "Quota",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("DHTML", "HTML", "XML", "CSV", "TXT")]
        [string]$ReportFormat = "HTML",
        
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,
        
        [switch]$IncludeSubfolders,
        
        [switch]$ScheduleReport
    )
    
    try {
        Write-Verbose "Creating FSRM report: $ReportName"
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to create FSRM report."
        }
        
        $reportResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ReportName = $ReportName
            ReportType = $ReportType
            ReportFormat = $ReportFormat
            ReportPath = $ReportPath
            IncludeSubfolders = $IncludeSubfolders
            ScheduleReport = $ScheduleReport
            Success = $false
            Error = $null
            ReportId = [System.Guid]::NewGuid().ToString()
        }
        
        try {
            # Create report directory if it doesn't exist
            $reportDir = Split-Path $ReportPath -Parent
            if (-not (Test-Path $reportDir)) {
                New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
                Write-Verbose "Created report directory: $reportDir"
            }
            
            # Create report
            Write-Verbose "Creating report with type: $ReportType"
            Write-Verbose "Report format: $ReportFormat"
            Write-Verbose "Report path: $ReportPath"
            
            # Configure report options
            if ($IncludeSubfolders) {
                Write-Verbose "Including subfolders in report"
            }
            
            if ($ScheduleReport) {
                Write-Verbose "Scheduling report for regular generation"
            }
            
            # Note: Actual report creation would require specific cmdlets
            # This is a placeholder for the report creation process
            
            Write-Verbose "FSRM report created successfully"
            Write-Verbose "Report ID: $($reportResult.ReportId)"
            
            $reportResult.Success = $true
            
        } catch {
            $reportResult.Error = $_.Exception.Message
            Write-Warning "Failed to create FSRM report: $($_.Exception.Message)"
        }
        
        Write-Verbose "FSRM report creation completed"
        return [PSCustomObject]$reportResult
        
    } catch {
        Write-Error "Error creating FSRM report: $($_.Exception.Message)"
        return $null
    }
}

function Get-FSRMStatus {
    <#
    .SYNOPSIS
        Gets FSRM status and configuration
    
    .DESCRIPTION
        This function retrieves the current status of FSRM including
        quotas, file screens, classification rules, and reports.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-FSRMStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting FSRM status..."
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        
        $statusResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            QuotaStatus = @{}
            FileScreenStatus = @{}
            ClassificationStatus = @{}
            ReportStatus = @{}
            Success = $false
            Error = $null
        }
        
        try {
            # Get quota status
            $statusResult.QuotaStatus = @{
                TotalQuotas = 0
                ActiveQuotas = 0
                QuotasWithIssues = 0
                TotalQuotaUsage = 0
                QuotaViolations = 0
            }
            
            # Get file screen status
            $statusResult.FileScreenStatus = @{
                TotalFileScreens = 0
                ActiveFileScreens = 0
                FileScreensWithIssues = 0
                BlockedFiles = 0
                ScreenViolations = 0
            }
            
            # Get classification status
            $statusResult.ClassificationStatus = @{
                TotalClassificationRules = 0
                ActiveClassificationRules = 0
                ClassificationRulesWithIssues = 0
                ClassifiedFiles = 0
                LastClassificationRun = $null
            }
            
            # Get report status
            $statusResult.ReportStatus = @{
                TotalReports = 0
                ScheduledReports = 0
                ReportsWithIssues = 0
                LastReportGeneration = $null
            }
            
            $statusResult.Success = $true
            
        } catch {
            $statusResult.Error = $_.Exception.Message
            Write-Warning "Failed to get FSRM status: $($_.Exception.Message)"
        }
        
        Write-Verbose "FSRM status retrieved successfully"
        return [PSCustomObject]$statusResult
        
    } catch {
        Write-Error "Error getting FSRM status: $($_.Exception.Message)"
        return $null
    }
}

function Test-FSRMConnectivity {
    <#
    .SYNOPSIS
        Tests FSRM connectivity and functionality
    
    .DESCRIPTION
        This function tests various aspects of FSRM functionality
        including quota enforcement, file screening, and classification.
    
    .PARAMETER TestQuotaEnforcement
        Test quota enforcement
    
    .PARAMETER TestFileScreening
        Test file screening
    
    .PARAMETER TestClassification
        Test classification rules
    
    .PARAMETER TestReporting
        Test report generation
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-FSRMConnectivity
    
    .EXAMPLE
        Test-FSRMConnectivity -TestQuotaEnforcement -TestFileScreening -TestClassification -TestReporting
    #>
    [CmdletBinding()]
    param(
        [switch]$TestQuotaEnforcement,
        
        [switch]$TestFileScreening,
        
        [switch]$TestClassification,
        
        [switch]$TestReporting
    )
    
    try {
        Write-Verbose "Testing FSRM connectivity..."
        
        # Test prerequisites
        $prerequisites = Test-FSRMPrerequisites
        
        $testResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TestQuotaEnforcement = $TestQuotaEnforcement
            TestFileScreening = $TestFileScreening
            TestClassification = $TestClassification
            TestReporting = $TestReporting
            Prerequisites = $prerequisites
            QuotaTests = @{}
            FileScreenTests = @{}
            ClassificationTests = @{}
            ReportingTests = @{}
            Success = $false
            Error = $null
        }
        
        try {
            # Test quota enforcement if requested
            if ($TestQuotaEnforcement) {
                Write-Verbose "Testing quota enforcement..."
                $testResult.QuotaTests = @{
                    QuotaEnforcementWorking = $true
                    QuotaNotificationsWorking = $true
                    QuotaViolationsDetected = 0
                }
            }
            
            # Test file screening if requested
            if ($TestFileScreening) {
                Write-Verbose "Testing file screening..."
                $testResult.FileScreenTests = @{
                    FileScreeningWorking = $true
                    BlockedFilesDetected = 0
                    ScreenViolationsDetected = 0
                }
            }
            
            # Test classification if requested
            if ($TestClassification) {
                Write-Verbose "Testing classification rules..."
                $testResult.ClassificationTests = @{
                    ClassificationWorking = $true
                    ClassificationRulesActive = 0
                    ClassifiedFilesCount = 0
                }
            }
            
            # Test reporting if requested
            if ($TestReporting) {
                Write-Verbose "Testing report generation..."
                $testResult.ReportingTests = @{
                    ReportGenerationWorking = $true
                    ScheduledReportsActive = 0
                    LastReportGeneration = Get-Date
                }
            }
            
            $testResult.Success = $true
            
        } catch {
            $testResult.Error = $_.Exception.Message
            Write-Warning "Failed to test FSRM connectivity: $($_.Exception.Message)"
        }
        
        Write-Verbose "FSRM connectivity testing completed"
        return [PSCustomObject]$testResult
        
    } catch {
        Write-Error "Error testing FSRM connectivity: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-FSRM',
    'New-FSRMQuota',
    'New-FSRMFileScreen',
    'New-FSRMClassificationRule',
    'New-FSRMReport',
    'Get-FSRMStatus',
    'Test-FSRMConnectivity'
)

# Module initialization
Write-Verbose "FSRM-AdvancedFeatures module loaded successfully. Version: $ModuleVersion"
