#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Sharing Management Script

.DESCRIPTION
    This script provides comprehensive file sharing management including share creation,
    permission management, and share configuration.

.PARAMETER Action
    The action to perform (Create, Remove, Configure, Report, Backup, Restore)

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

.PARAMETER CachingMode
    Offline files caching mode (Manual, Documents, Programs, None)

.PARAMETER OutputPath
    Path to save reports or backups

.PARAMETER BackupPath
    Path to restore configuration from

.PARAMETER IncludePermissions
    Include detailed permission information in reports

.PARAMETER IncludeUsage
    Include usage statistics in reports

.EXAMPLE
    .\Manage-FileShares.ps1 -Action Create -ShareName "Data" -Path "C:\Shares\Data" -Description "Data Share" -FullAccess @("Administrators") -ReadAccess @("Users")

.EXAMPLE
    .\Manage-FileShares.ps1 -Action Configure -ShareName "Data" -EnableAccessBasedEnumeration -EnableOfflineFiles -CachingMode "Documents"

.EXAMPLE
    .\Manage-FileShares.ps1 -Action Report -OutputPath "C:\Reports\FileShares.html" -IncludePermissions -IncludeUsage

.EXAMPLE
    .\Manage-FileShares.ps1 -Action Backup -OutputPath "C:\Backups\FileShares.xml"

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Create", "Remove", "Configure", "Report", "Backup", "Restore")]
    [string]$Action,
    
    [string]$ShareName,
    
    [string]$Path,
    
    [string]$Description,
    
    [string[]]$FullAccess,
    
    [string[]]$ReadAccess,
    
    [string[]]$ChangeAccess,
    
    [switch]$EnableAccessBasedEnumeration,
    
    [switch]$EnableOfflineFiles,
    
    [ValidateSet("Manual", "Documents", "Programs", "None")]
    [string]$CachingMode = "Manual",
    
    [string]$OutputPath,
    
    [string]$BackupPath,
    
    [switch]$IncludePermissions,
    
    [switch]$IncludeUsage
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:ManagementLog = @()
$script:StartTime = Get-Date

function Write-ManagementLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:ManagementLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function New-FileShareConfiguration {
    param(
        [string]$ShareName,
        [string]$Path,
        [string]$Description,
        [string[]]$FullAccess,
        [string[]]$ReadAccess,
        [string[]]$ChangeAccess,
        [switch]$EnableAccessBasedEnumeration,
        [switch]$EnableOfflineFiles,
        [string]$CachingMode
    )
    
    Write-ManagementLog "Creating file share: $ShareName" "INFO"
    
    try {
        $shareParams = @{
            ShareName = $ShareName
            Path = $Path
            Description = $Description
        }
        
        if ($FullAccess) { $shareParams.FullAccess = $FullAccess }
        if ($ReadAccess) { $shareParams.ReadAccess = $ReadAccess }
        if ($ChangeAccess) { $shareParams.ChangeAccess = $ChangeAccess }
        if ($EnableAccessBasedEnumeration) { $shareParams.EnableAccessBasedEnumeration = $true }
        if ($EnableOfflineFiles) { $shareParams.EnableOfflineFiles = $true }
        
        New-FileShare @shareParams
        
        # Configure caching mode if offline files is enabled
        if ($EnableOfflineFiles -and $CachingMode) {
            Set-SmbShare -Name $ShareName -CachingMode $CachingMode
            Write-ManagementLog "Set caching mode to: $CachingMode" "SUCCESS"
        }
        
        Write-ManagementLog "File share created successfully: $ShareName" "SUCCESS"
        return $true
        
    } catch {
        Write-ManagementLog "Failed to create file share: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-FileShareConfiguration {
    param(
        [string]$ShareName,
        [switch]$RemoveDirectory
    )
    
    Write-ManagementLog "Removing file share: $ShareName" "INFO"
    
    try {
        Remove-FileShare -ShareName $ShareName -RemoveDirectory:$RemoveDirectory -Force
        Write-ManagementLog "File share removed successfully: $ShareName" "SUCCESS"
        return $true
        
    } catch {
        Write-ManagementLog "Failed to remove file share: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Update-FileShareConfiguration {
    param(
        [string]$ShareName,
        [string]$Description,
        [switch]$EnableAccessBasedEnumeration,
        [switch]$EnableOfflineFiles,
        [string]$CachingMode
    )
    
    Write-ManagementLog "Configuring file share: $ShareName" "INFO"
    
    try {
        # Check if share exists
        $share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
        if (-not $share) {
            Write-ManagementLog "Share not found: $ShareName" "ERROR"
            return $false
        }
        
        # Update description if provided
        if ($Description) {
            Set-SmbShare -Name $ShareName -Description $Description
            Write-ManagementLog "Updated description for share: $ShareName" "SUCCESS"
        }
        
        # Update access-based enumeration
        if ($PSBoundParameters.ContainsKey('EnableAccessBasedEnumeration')) {
            Set-SmbShare -Name $ShareName -FolderEnumerationMode $(if ($EnableAccessBasedEnumeration) { 'AccessBased' } else { 'Unrestricted' })
            Write-ManagementLog "Updated access-based enumeration for share: $ShareName" "SUCCESS"
        }
        
        # Update offline files caching
        if ($EnableOfflineFiles -and $CachingMode) {
            Set-SmbShare -Name $ShareName -CachingMode $CachingMode
            Write-ManagementLog "Updated caching mode for share: $ShareName" "SUCCESS"
        }
        
        Write-ManagementLog "File share configuration updated successfully: $ShareName" "SUCCESS"
        return $true
        
    } catch {
        Write-ManagementLog "Failed to configure file share: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-FileShareBackup {
    param([string]$OutputPath)
    
    Write-ManagementLog "Creating file share backup..." "INFO"
    
    try {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $scriptPath "FileShares-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
        }
        
        $backup = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Shares = @()
        }
        
        # Get all shares
        $shares = Get-SmbShare | Where-Object { $_.ShareType -eq 'FileSystemDirectory' }
        
        foreach ($share in $shares) {
            $shareInfo = @{
                Name = $share.Name
                Path = $share.Path
                Description = $share.Description
                FolderEnumerationMode = $share.FolderEnumerationMode
                CachingMode = $share.CachingMode
                Permissions = @()
            }
            
            # Get permissions
            try {
                $permissions = Get-SmbShareAccess -Name $share.Name
                $shareInfo.Permissions = $permissions | Select-Object AccountName, AccessRight, AccessType
            } catch {
                Write-Warning "Could not retrieve permissions for share: $($share.Name)"
            }
            
            $backup.Shares += $shareInfo
        }
        
        # Save backup
        $backup | Export-Clixml -Path $OutputPath -Force
        
        Write-ManagementLog "File share backup saved to: $OutputPath" "SUCCESS"
        return $OutputPath
        
    } catch {
        Write-ManagementLog "Failed to create file share backup: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Restore-FileShareBackup {
    param([string]$BackupPath)
    
    Write-ManagementLog "Restoring file share backup..." "INFO"
    
    try {
        if (-not (Test-Path $BackupPath)) {
            throw "Backup file not found: $BackupPath"
        }
        
        # Load backup
        $backup = Import-Clixml -Path $BackupPath
        
        Write-ManagementLog "Restoring configuration from: $($backup.Timestamp)" "INFO"
        
        $restoredCount = 0
        $errorCount = 0
        
        foreach ($shareInfo in $backup.Shares) {
            try {
                # Check if share already exists
                $existingShare = Get-SmbShare -Name $shareInfo.Name -ErrorAction SilentlyContinue
                
                if ($existingShare) {
                    Write-ManagementLog "Share already exists, skipping: $($shareInfo.Name)" "WARNING"
                    continue
                }
                
                # Ensure the path exists
                if (-not (Test-Path $shareInfo.Path)) {
                    New-Item -Path $shareInfo.Path -ItemType Directory -Force | Out-Null
                }
                
                # Create the share
                $shareParams = @{
                    Name = $shareInfo.Name
                    Path = $shareInfo.Path
                    Description = $shareInfo.Description
                }
                
                if ($shareInfo.FolderEnumerationMode -eq 'AccessBased') {
                    $shareParams.AccessBasedEnumeration = $true
                }
                
                New-SmbShare @shareParams
                
                # Set caching mode
                if ($shareInfo.CachingMode) {
                    Set-SmbShare -Name $shareInfo.Name -CachingMode $shareInfo.CachingMode
                }
                
                # Restore permissions
                foreach ($permission in $shareInfo.Permissions) {
                    try {
                        Grant-SmbShareAccess -Name $shareInfo.Name -AccountName $permission.AccountName -AccessRight $permission.AccessRight -AccessType $permission.AccessType -Force
                    } catch {
                        Write-Warning "Could not restore permission for $($permission.AccountName) on share $($shareInfo.Name)"
                    }
                }
                
                $restoredCount++
                Write-ManagementLog "Restored share: $($shareInfo.Name)" "SUCCESS"
                
            } catch {
                $errorCount++
                Write-ManagementLog "Failed to restore share $($shareInfo.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        Write-ManagementLog "File share backup restore completed. Restored: $restoredCount, Errors: $errorCount" "SUCCESS"
        return $true
        
    } catch {
        Write-ManagementLog "Failed to restore file share backup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-ManagementLog {
    $logPath = Join-Path $scriptPath "Management-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:ManagementLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-ManagementLog "Management log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save management log: $($_.Exception.Message)"
    }
}

# Main file share management process
try {
    Write-ManagementLog "Starting file share management..." "INFO"
    Write-ManagementLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "Create" {
            if (-not $ShareName -or -not $Path) {
                throw "ShareName and Path parameters are required for Create action"
            }
            
            if (-not (New-FileShareConfiguration -ShareName $ShareName -Path $Path -Description $Description -FullAccess $FullAccess -ReadAccess $ReadAccess -ChangeAccess $ChangeAccess -EnableAccessBasedEnumeration:$EnableAccessBasedEnumeration -EnableOfflineFiles:$EnableOfflineFiles -CachingMode $CachingMode)) {
                throw "File share creation failed"
            }
        }
        
        "Remove" {
            if (-not $ShareName) {
                throw "ShareName parameter is required for Remove action"
            }
            
            if (-not (Remove-FileShareConfiguration -ShareName $ShareName)) {
                throw "File share removal failed"
            }
        }
        
        "Configure" {
            if (-not $ShareName) {
                throw "ShareName parameter is required for Configure action"
            }
            
            if (-not (Update-FileShareConfiguration -ShareName $ShareName -Description $Description -EnableAccessBasedEnumeration:$EnableAccessBasedEnumeration -EnableOfflineFiles:$EnableOfflineFiles -CachingMode $CachingMode)) {
                throw "File share configuration failed"
            }
        }
        
        "Report" {
            $report = Get-FileShareReport -OutputPath $OutputPath -IncludePermissions:$IncludePermissions -IncludeUsage:$IncludeUsage
            if ($report) {
                Write-Host "`n=== File Share Report ===" -ForegroundColor Cyan
                Write-Host "Total Shares: $($report.Summary.TotalShares)" -ForegroundColor White
                Write-Host "Online Shares: $($report.Summary.OnlineShares)" -ForegroundColor White
                Write-Host "Offline Shares: $($report.Summary.OfflineShares)" -ForegroundColor White
            }
        }
        
        "Backup" {
            $backupPath = New-FileShareBackup -OutputPath $OutputPath
            if ($backupPath) {
                Write-Host "`nFile share backup created: $backupPath" -ForegroundColor Green
            } else {
                throw "File share backup failed"
            }
        }
        
        "Restore" {
            if (-not $BackupPath) {
                throw "BackupPath parameter is required for Restore action"
            }
            
            if (-not (Restore-FileShareBackup -BackupPath $BackupPath)) {
                throw "File share restore failed"
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ManagementLog "File share management completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== File Share Management Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save management log
    Save-ManagementLog
    
    Write-Host "`nFile share management completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ManagementLog "File share management failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save management log
    Save-ManagementLog
    
    Write-Host "`nFile share management failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the management log for details." -ForegroundColor Yellow
    
    exit 1
}
