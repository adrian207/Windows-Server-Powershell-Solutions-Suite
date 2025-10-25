#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Management PowerShell Module

.DESCRIPTION
    This module provides functions for managing Windows File Servers including
    share management, permissions, DFS configuration, and FSRM setup.

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module FileStorage-Core -ErrorAction Stop
    Import-Module SmbShare -ErrorAction Stop
    Import-Module Dfsn -ErrorAction SilentlyContinue
    Import-Module Dfsr -ErrorAction SilentlyContinue
    Import-Module FileServerResourceManager -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not found. Some functions may not work properly."
}

#region Private Functions

function Test-SmbShareExists {
    <#
    .SYNOPSIS
        Tests if an SMB share exists
    
    .PARAMETER ShareName
        The name of the share to test
    
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareName
    )
    
    try {
        $share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
        return $null -ne $share
    } catch {
        return $false
    }
}

function Get-SharePermissions {
    <#
    .SYNOPSIS
        Gets permissions for a specific share
    
    .PARAMETER ShareName
        The name of the share
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareName
    )
    
    try {
        $sharePermissions = Get-SmbShareAccess -Name $ShareName -ErrorAction SilentlyContinue
        return $sharePermissions
    } catch {
        Write-Warning "Could not retrieve permissions for share: $ShareName"
        return @()
    }
}

function Set-SharePermissions {
    <#
    .SYNOPSIS
        Sets permissions for a specific share
    
    .PARAMETER ShareName
        The name of the share
    
    .PARAMETER AccountName
        The account name
    
    .PARAMETER AccessRight
        The access right (Read, Change, Full)
    
    .PARAMETER AccessType
        The access type (Allow, Deny)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Read", "Change", "Full")]
        [string]$AccessRight,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Allow", "Deny")]
        [string]$AccessType
    )
    
    try {
        Grant-SmbShareAccess -Name $ShareName -AccountName $AccountName -AccessRight $AccessRight -AccessType $AccessType -Force
        Write-Verbose "Set $AccessType $AccessRight permission for $AccountName on share $ShareName"
    } catch {
        Write-Error "Failed to set permissions for share $ShareName`: $($_.Exception.Message)"
        throw
    }
}

#endregion

#region Public Functions

function New-FileShare {
    <#
    .SYNOPSIS
        Creates a new file share
    
    .DESCRIPTION
        Creates a new SMB file share with specified permissions and settings
    
    .PARAMETER ShareName
        The name of the share
    
    .PARAMETER Path
        The local path to share
    
    .PARAMETER Description
        Description for the share
    
    .PARAMETER FullAccess
        Array of accounts with full access
    
    .PARAMETER ReadAccess
        Array of accounts with read access
    
    .PARAMETER ChangeAccess
        Array of accounts with change access
    
    .PARAMETER EnableAccessBasedEnumeration
        Enable access-based enumeration
    
    .PARAMETER EnableOfflineFiles
        Enable offline files caching
    
    .EXAMPLE
        New-FileShare -ShareName "Data" -Path "C:\Shares\Data" -Description "Data Share" -FullAccess @("Administrators") -ReadAccess @("Users")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [string]$Description = "",
        
        [string[]]$FullAccess = @(),
        
        [string[]]$ReadAccess = @(),
        
        [string[]]$ChangeAccess = @(),
        
        [switch]$EnableAccessBasedEnumeration,
        
        [switch]$EnableOfflineFiles
    )
    
    try {
        Write-Host "Creating file share: $ShareName" -ForegroundColor Green
        
        # Check if share already exists
        if (Test-SmbShareExists -ShareName $ShareName) {
            Write-Warning "Share '$ShareName' already exists. Skipping creation."
            return
        }
        
        # Ensure the path exists
        if (-not (Test-Path $Path)) {
            Write-Host "Creating directory: $Path" -ForegroundColor Yellow
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
        
        # Create the share
        $shareParams = @{
            Name = $ShareName
            Path = $Path
            Description = $Description
        }
        
        if ($EnableAccessBasedEnumeration) {
            $shareParams.AccessBasedEnumeration = $true
        }
        
        if ($EnableOfflineFiles) {
            $shareParams.CachingMode = "Manual"
        }
        
        New-SmbShare @shareParams
        
        Write-Host "Share created successfully: $ShareName" -ForegroundColor Green
        
        # Set permissions
        foreach ($account in $FullAccess) {
            Set-SharePermissions -ShareName $ShareName -AccountName $account -AccessRight "Full" -AccessType "Allow"
        }
        
        foreach ($account in $ChangeAccess) {
            Set-SharePermissions -ShareName $ShareName -AccountName $account -AccessRight "Change" -AccessType "Allow"
        }
        
        foreach ($account in $ReadAccess) {
            Set-SharePermissions -ShareName $ShareName -AccountName $account -AccessRight "Read" -AccessType "Allow"
        }
        
        Write-Host "Permissions configured for share: $ShareName" -ForegroundColor Green
        
    } catch {
        Write-Error "Error creating file share: $($_.Exception.Message)"
        throw
    }
}

function Remove-FileShare {
    <#
    .SYNOPSIS
        Removes a file share
    
    .DESCRIPTION
        Removes an SMB file share and optionally the underlying directory
    
    .PARAMETER ShareName
        The name of the share to remove
    
    .PARAMETER RemoveDirectory
        Remove the underlying directory
    
    .PARAMETER Force
        Force removal without confirmation
    
    .EXAMPLE
        Remove-FileShare -ShareName "TempShare" -RemoveDirectory
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [switch]$RemoveDirectory,
        
        [switch]$Force
    )
    
    try {
        if (-not (Test-SmbShareExists -ShareName $ShareName)) {
            Write-Warning "Share '$ShareName' does not exist."
            return
        }
        
        if ($PSCmdlet.ShouldProcess("File Share '$ShareName'", "Remove")) {
            Write-Host "Removing file share: $ShareName" -ForegroundColor Yellow
            
            # Get share path before removal
            $share = Get-SmbShare -Name $ShareName
            $sharePath = $share.Path
            
            # Remove the share
            Remove-SmbShare -Name $ShareName -Force
            
            Write-Host "Share removed successfully: $ShareName" -ForegroundColor Green
            
            # Remove directory if requested
            if ($RemoveDirectory -and $sharePath) {
                if (Test-Path $sharePath) {
                    Write-Host "Removing directory: $sharePath" -ForegroundColor Yellow
                    Remove-Item -Path $sharePath -Recurse -Force
                    Write-Host "Directory removed successfully: $sharePath" -ForegroundColor Green
                }
            }
        }
        
    } catch {
        Write-Error "Error removing file share: $($_.Exception.Message)"
        throw
    }
}

function Get-FileShareReport {
    <#
    .SYNOPSIS
        Generates a comprehensive file share report
    
    .DESCRIPTION
        Creates a detailed report of all file shares, their permissions, and usage
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER IncludePermissions
        Include detailed permission information
    
    .PARAMETER IncludeUsage
        Include usage statistics
    
    .EXAMPLE
        Get-FileShareReport -OutputPath "C:\Reports\FileShares.html" -IncludePermissions
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludePermissions,
        
        [switch]$IncludeUsage
    )
    
    try {
        Write-Host "Generating file share report..." -ForegroundColor Green
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Shares = @()
            Summary = @{}
        }
        
        # Get all shares
        $shares = Get-SmbShare | Where-Object { $_.ShareType -eq 'FileSystemDirectory' }
        
        foreach ($share in $shares) {
            $shareInfo = @{
                Name = $share.Name
                Path = $share.Path
                Description = $share.Description
                ShareState = $share.ShareState
                ShareType = $share.ShareType
                FolderEnumerationMode = $share.FolderEnumerationMode
                CachingMode = $share.CachingMode
            }
            
            if ($IncludePermissions) {
                $shareInfo.Permissions = Get-SharePermissions -ShareName $share.Name
            }
            
            if ($IncludeUsage) {
                try {
                    $shareInfo.SessionCount = (Get-SmbSession -ShareName $share.Name -ErrorAction SilentlyContinue).Count
                    $shareInfo.OpenFileCount = (Get-SmbOpenFile -ShareName $share.Name -ErrorAction SilentlyContinue).Count
                } catch {
                    $shareInfo.SessionCount = 0
                    $shareInfo.OpenFileCount = 0
                }
            }
            
            $report.Shares += $shareInfo
        }
        
        # Generate summary
        $report.Summary = @{
            TotalShares = $shares.Count
            OnlineShares = ($shares | Where-Object { $_.ShareState -eq 'Online' }).Count
            OfflineShares = ($shares | Where-Object { $_.ShareState -eq 'Offline' }).Count
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "File Share Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
</style>
"@
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating file share report: $($_.Exception.Message)"
        throw
    }
}

function Set-FileServerConfiguration {
    <#
    .SYNOPSIS
        Configures file server settings
    
    .DESCRIPTION
        Configures various file server settings including SMB protocol versions,
        security settings, and performance options
    
    .PARAMETER EnableSMB1
        Enable SMB 1.0 protocol
    
    .PARAMETER EnableSMB2
        Enable SMB 2.0 protocol
    
    .PARAMETER EnableSMB3
        Enable SMB 3.0 protocol
    
    .PARAMETER RequireSigning
        Require SMB signing
    
    .PARAMETER EnableEncryption
        Enable SMB encryption
    
    .PARAMETER MaxConnections
        Maximum number of connections per share
    
    .EXAMPLE
        Set-FileServerConfiguration -EnableSMB3 -RequireSigning -EnableEncryption
    #>
    [CmdletBinding()]
    param(
        [switch]$EnableSMB1,
        
        [switch]$EnableSMB2,
        
        [switch]$EnableSMB3,
        
        [switch]$RequireSigning,
        
        [switch]$EnableEncryption,
        
        [int]$MaxConnections = 16777216
    )
    
    try {
        Write-Host "Configuring file server settings..." -ForegroundColor Green
        
        # Get current SMB server configuration
        $smbConfig = Get-SmbServerConfiguration
        
        # Configure SMB protocol versions
        if ($PSBoundParameters.ContainsKey('EnableSMB1')) {
            $smbConfig.EnableSMB1Protocol = $EnableSMB1
            Write-Host "SMB 1.0 protocol: $EnableSMB1" -ForegroundColor Yellow
        }
        
        if ($PSBoundParameters.ContainsKey('EnableSMB2')) {
            $smbConfig.EnableSMB2Protocol = $EnableSMB2
            Write-Host "SMB 2.0 protocol: $EnableSMB2" -ForegroundColor Yellow
        }
        
        if ($PSBoundParameters.ContainsKey('EnableSMB3')) {
            $smbConfig.EnableSMB3Protocol = $EnableSMB3
            Write-Host "SMB 3.0 protocol: $EnableSMB3" -ForegroundColor Yellow
        }
        
        # Configure security settings
        if ($PSBoundParameters.ContainsKey('RequireSigning')) {
            $smbConfig.RequireSecuritySignature = $RequireSigning
            Write-Host "SMB signing required: $RequireSigning" -ForegroundColor Yellow
        }
        
        if ($PSBoundParameters.ContainsKey('EnableEncryption')) {
            $smbConfig.EncryptData = $EnableEncryption
            Write-Host "SMB encryption enabled: $EnableEncryption" -ForegroundColor Yellow
        }
        
        # Configure performance settings
        $smbConfig.MaxMpxCount = $MaxConnections
        Write-Host "Maximum connections: $MaxConnections" -ForegroundColor Yellow
        
        # Apply configuration
        Set-SmbServerConfiguration -InputObject $smbConfig -Force
        
        Write-Host "File server configuration completed successfully" -ForegroundColor Green
        
    } catch {
        Write-Error "Error configuring file server: $($_.Exception.Message)"
        throw
    }
}

function Enable-FSRM {
    <#
    .SYNOPSIS
        Enables and configures File Server Resource Manager
    
    .DESCRIPTION
        Installs and configures FSRM for quota management, file screening, and reporting
    
    .PARAMETER EnableQuotas
        Enable disk quotas
    
    .PARAMETER EnableFileScreening
        Enable file screening
    
    .PARAMETER EnableReporting
        Enable reporting
    
    .PARAMETER QuotaTemplate
        Path to quota template file
    
    .PARAMETER ScreenTemplate
        Path to file screen template file
    
    .EXAMPLE
        Enable-FSRM -EnableQuotas -EnableFileScreening -EnableReporting
    #>
    [CmdletBinding()]
    param(
        [switch]$EnableQuotas,
        
        [switch]$EnableFileScreening,
        
        [switch]$EnableReporting,
        
        [string]$QuotaTemplate,
        
        [string]$ScreenTemplate
    )
    
    try {
        Write-Host "Enabling File Server Resource Manager..." -ForegroundColor Green
        
        # Install FSRM feature if not already installed
        $fsrmFeature = Get-WindowsFeature -Name FS-Resource-Manager
        if ($fsrmFeature.InstallState -ne 'Installed') {
            Write-Host "Installing FSRM feature..." -ForegroundColor Yellow
            Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
        }
        
        # Start FSRM service
        $fsrmService = Get-Service -Name FsrmSvc -ErrorAction SilentlyContinue
        if ($fsrmService -and $fsrmService.Status -ne 'Running') {
            Start-Service -Name FsrmSvc
            Write-Host "FSRM service started" -ForegroundColor Green
        }
        
        # Configure quotas if enabled
        if ($EnableQuotas) {
            Write-Host "Configuring disk quotas..." -ForegroundColor Yellow
            
            # Import quota templates if provided
            if ($QuotaTemplate -and (Test-Path $QuotaTemplate)) {
                Import-FsrmQuotaTemplate -Path $QuotaTemplate
                Write-Host "Quota templates imported from: $QuotaTemplate" -ForegroundColor Green
            }
        }
        
        # Configure file screening if enabled
        if ($EnableFileScreening) {
            Write-Host "Configuring file screening..." -ForegroundColor Yellow
            
            # Import file screen templates if provided
            if ($ScreenTemplate -and (Test-Path $ScreenTemplate)) {
                Import-FsrmFileScreenTemplate -Path $ScreenTemplate
                Write-Host "File screen templates imported from: $ScreenTemplate" -ForegroundColor Green
            }
        }
        
        # Configure reporting if enabled
        if ($EnableReporting) {
            Write-Host "Configuring reporting..." -ForegroundColor Yellow
            
            # Set up default reports
            $reportTypes = @('DuplicateFiles', 'LargeFiles', 'LeastRecentlyAccessedFiles', 'MostRecentlyAccessedFiles', 'QuotaUsage')
            foreach ($reportType in $reportTypes) {
                try {
                    New-FsrmReportJob -Name "Default_$reportType" -ReportType $reportType -Schedule Weekly -ErrorAction SilentlyContinue
                } catch {
                    Write-Verbose "Report job for $reportType may already exist"
                }
            }
        }
        
        Write-Host "FSRM configuration completed successfully" -ForegroundColor Green
        
    } catch {
        Write-Error "Error configuring FSRM: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'New-FileShare',
    'Remove-FileShare',
    'Get-FileShareReport',
    'Set-FileServerConfiguration',
    'Enable-FSRM'
)

# Module initialization
Write-Verbose "FileStorage-Management module loaded successfully. Version: $ModuleVersion"