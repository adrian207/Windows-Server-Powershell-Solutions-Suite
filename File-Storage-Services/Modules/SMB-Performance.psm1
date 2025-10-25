#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    SMB Performance Tuning PowerShell Module

.DESCRIPTION
    This module provides comprehensive SMB performance tuning capabilities based on
    Microsoft's official performance tuning guidelines for file servers.

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/file-server/
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Get-SMBRegistrySettings {
    <#
    .SYNOPSIS
        Gets current SMB registry settings
    
    .DESCRIPTION
        Retrieves current SMB performance tuning registry settings
    #>
    [CmdletBinding()]
    param()
    
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $settings = @{}
    
    $settingNames = @(
        'ConnectionCountPerNetworkInterface',
        'ConnectionCountPerRssNetworkInterface', 
        'ConnectionCountPerRdmaNetworkInterface',
        'MaximumConnectionCountPerServer',
        'DormantDirectoryTimeout',
        'FileInfoCacheLifetime',
        'DirectoryCacheLifetime',
        'DirectoryCacheEntrySizeMax',
        'FileNotFoundCacheLifetime',
        'CacheFileTimeout',
        'DisableBandwidthThrottling',
        'DisableLargeMtu',
        'RequireSecuritySignature',
        'FileInfoCacheEntriesMax',
        'DirectoryCacheEntriesMax',
        'FileNotFoundCacheEntriesMax',
        'MaxCmds',
        'DormantFileLimit'
    )
    
    foreach ($settingName in $settingNames) {
        try {
            $value = Get-ItemProperty -Path $registryPath -Name $settingName -ErrorAction SilentlyContinue
            if ($value) {
                $settings[$settingName] = $value.$settingName
            } else {
                $settings[$settingName] = "Not Set"
            }
        } catch {
            $settings[$settingName] = "Error: $($_.Exception.Message)"
        }
    }
    
    return $settings
}

function Set-SMBRegistrySetting {
    <#
    .SYNOPSIS
        Sets an SMB registry setting
    
    .PARAMETER SettingName
        Name of the registry setting
    .PARAMETER Value
        Value to set
    .PARAMETER RegistryPath
        Registry path (default: LanmanWorkstation Parameters)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SettingName,
        
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [string]$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    )
    
    try {
        Set-ItemProperty -Path $RegistryPath -Name $SettingName -Value $Value -Force
        Write-Verbose "Set registry setting $SettingName to $Value"
        return $true
    } catch {
        Write-Error "Failed to set registry setting $SettingName`: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region Public Functions

function Get-SMBPerformanceSettings {
    <#
    .SYNOPSIS
        Gets current SMB performance settings
    
    .DESCRIPTION
        Retrieves current SMB performance tuning settings from both registry and PowerShell cmdlets
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-SMBPerformanceSettings
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting SMB performance settings..."
        
        $settings = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            RegistrySettings = @{}
            PowerShellSettings = @{}
            Recommendations = @()
        }
        
        # Get registry settings
        $settings.RegistrySettings = Get-SMBRegistrySettings
        
        # Get PowerShell SMB settings
        try {
            $smbClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
            $smbServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            
            $settings.PowerShellSettings.Client = $smbClientConfig
            $settings.PowerShellSettings.Server = $smbServerConfig
        } catch {
            Write-Warning "Could not retrieve SMB PowerShell settings: $($_.Exception.Message)"
        }
        
        # Generate recommendations
        if ($settings.RegistrySettings.DisableBandwidthThrottling -eq 0) {
            $settings.Recommendations += "Consider setting DisableBandwidthThrottling to 1 for high-latency networks"
        }
        
        if ($settings.RegistrySettings.FileInfoCacheEntriesMax -lt 32768) {
            $settings.Recommendations += "Consider increasing FileInfoCacheEntriesMax to 32768 for better performance"
        }
        
        if ($settings.RegistrySettings.DirectoryCacheEntriesMax -lt 4096) {
            $settings.Recommendations += "Consider increasing DirectoryCacheEntriesMax to 4096 for large directories"
        }
        
        if ($settings.RegistrySettings.MaxCmds -lt 32768) {
            $settings.Recommendations += "Consider increasing MaxCmds to 32768 for better pipeline performance"
        }
        
        Write-Verbose "SMB performance settings retrieved successfully"
        return [PSCustomObject]$settings
        
    } catch {
        Write-Error "Error getting SMB performance settings: $($_.Exception.Message)"
        return $null
    }
}

function Set-SMBPerformanceOptimization {
    <#
    .SYNOPSIS
        Applies Microsoft-recommended SMB performance optimizations
    
    .DESCRIPTION
        Applies the Microsoft-recommended performance tuning settings for file servers
        based on the official documentation
    
    .PARAMETER OptimizationLevel
        Level of optimization (Basic, HighLatency, Enterprise, Custom)
    
    .PARAMETER CustomSettings
        Custom settings hashtable for Custom optimization level
    
    .PARAMETER RestartRequired
        Whether a restart is required for changes to take effect
    
    .EXAMPLE
        Set-SMBPerformanceOptimization -OptimizationLevel "HighLatency"
    
    .EXAMPLE
        Set-SMBPerformanceOptimization -OptimizationLevel "Custom" -CustomSettings @{DisableBandwidthThrottling=1; FileInfoCacheEntriesMax=32768}
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Basic", "HighLatency", "Enterprise", "Custom")]
        [string]$OptimizationLevel = "Basic",
        
        [hashtable]$CustomSettings,
        
        [switch]$RestartRequired
    )
    
    try {
        Write-Host "Applying SMB performance optimization: $OptimizationLevel" -ForegroundColor Green
        
        $optimizationResults = @{
            OptimizationLevel = $OptimizationLevel
            SettingsApplied = @{}
            Errors = @()
            RestartRequired = $false
        }
        
        # Define optimization profiles based on Microsoft documentation
        $optimizationProfiles = @{
            Basic = @{
                DisableBandwidthThrottling = 0
                FileInfoCacheEntriesMax = 64
                DirectoryCacheEntriesMax = 16
                FileNotFoundCacheEntriesMax = 128
                MaxCmds = 15
                RequireSecuritySignature = 0
            }
            
            HighLatency = @{
                DisableBandwidthThrottling = 1
                FileInfoCacheEntriesMax = 32768
                DirectoryCacheEntriesMax = 4096
                FileNotFoundCacheEntriesMax = 32768
                MaxCmds = 32768
                RequireSecuritySignature = 0
            }
            
            Enterprise = @{
                DisableBandwidthThrottling = 1
                FileInfoCacheEntriesMax = 65536
                DirectoryCacheEntriesMax = 4096
                FileNotFoundCacheEntriesMax = 65536
                MaxCmds = 32768
                RequireSecuritySignature = 0
                ConnectionCountPerNetworkInterface = 4
                ConnectionCountPerRssNetworkInterface = 8
                MaximumConnectionCountPerServer = 64
            }
            
            Custom = $CustomSettings
        }
        
        $settingsToApply = $optimizationProfiles[$OptimizationLevel]
        
        if (-not $settingsToApply) {
            throw "Invalid optimization level: $OptimizationLevel"
        }
        
        # Apply registry settings
        foreach ($settingName in $settingsToApply.Keys) {
            try {
                $result = Set-SMBRegistrySetting -SettingName $settingName -Value $settingsToApply[$settingName]
                if ($result) {
                    $optimizationResults.SettingsApplied[$settingName] = $settingsToApply[$settingName]
                    Write-Host "Applied setting: $settingName = $($settingsToApply[$settingName])" -ForegroundColor Green
                } else {
                    $optimizationResults.Errors += "Failed to apply $settingName"
                }
            } catch {
                $optimizationResults.Errors += "Error applying $settingName`: $($_.Exception.Message)"
            }
        }
        
        # Apply PowerShell SMB settings
        try {
            if ($OptimizationLevel -eq "HighLatency" -or $OptimizationLevel -eq "Enterprise") {
                # Disable bandwidth throttling via PowerShell if available
                try {
                    Set-SmbClientConfiguration -DisableBandwidthThrottling $true -Force -ErrorAction SilentlyContinue
                    Write-Host "Applied PowerShell SMB client configuration" -ForegroundColor Green
                } catch {
                    Write-Warning "Could not apply PowerShell SMB client configuration: $($_.Exception.Message)"
                }
            }
        } catch {
            $optimizationResults.Errors += "Error applying PowerShell SMB settings: $($_.Exception.Message)"
        }
        
        # Check if restart is required
        if ($OptimizationLevel -eq "Enterprise" -or $RestartRequired) {
            $optimizationResults.RestartRequired = $true
            Write-Host "Restart required for optimal performance" -ForegroundColor Yellow
        }
        
        Write-Host "SMB performance optimization completed: $OptimizationLevel" -ForegroundColor Green
        return [PSCustomObject]$optimizationResults
        
    } catch {
        Write-Error "Error applying SMB performance optimization: $($_.Exception.Message)"
        throw
    }
}

function Test-SMBPerformanceSettings {
    <#
    .SYNOPSIS
        Tests SMB performance settings against Microsoft recommendations
    
    .DESCRIPTION
        Validates current SMB settings against Microsoft's performance tuning guidelines
    
    .PARAMETER OptimizationLevel
        Optimization level to test against
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-SMBPerformanceSettings -OptimizationLevel "HighLatency"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Basic", "HighLatency", "Enterprise", "Custom")]
        [string]$OptimizationLevel = "HighLatency"
    )
    
    try {
        Write-Verbose "Testing SMB performance settings against $OptimizationLevel recommendations..."
        
        $testResults = @{
            OptimizationLevel = $OptimizationLevel
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            CurrentSettings = @{}
            RecommendedSettings = @{}
            Compliance = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Get current settings
        $currentSettings = Get-SMBRegistrySettings
        $testResults.CurrentSettings = $currentSettings
        
        # Define recommended settings
        $recommendedSettings = @{
            Basic = @{
                DisableBandwidthThrottling = 0
                FileInfoCacheEntriesMax = 64
                DirectoryCacheEntriesMax = 16
                FileNotFoundCacheEntriesMax = 128
                MaxCmds = 15
            }
            
            HighLatency = @{
                DisableBandwidthThrottling = 1
                FileInfoCacheEntriesMax = 32768
                DirectoryCacheEntriesMax = 4096
                FileNotFoundCacheEntriesMax = 32768
                MaxCmds = 32768
            }
            
            Enterprise = @{
                DisableBandwidthThrottling = 1
                FileInfoCacheEntriesMax = 65536
                DirectoryCacheEntriesMax = 4096
                FileNotFoundCacheEntriesMax = 65536
                MaxCmds = 32768
                ConnectionCountPerNetworkInterface = 4
                ConnectionCountPerRssNetworkInterface = 8
                MaximumConnectionCountPerServer = 64
            }
        }
        
        $testResults.RecommendedSettings = $recommendedSettings[$OptimizationLevel]
        
        # Compare settings
        foreach ($settingName in $recommendedSettings[$OptimizationLevel].Keys) {
            $currentValue = $currentSettings[$settingName]
            $recommendedValue = $recommendedSettings[$OptimizationLevel][$settingName]
            
            if ($currentValue -eq $recommendedValue) {
                $testResults.Compliance[$settingName] = "Compliant"
            } else {
                $testResults.Compliance[$settingName] = "Non-Compliant"
                $testResults.Issues += "$settingName: Current=$currentValue, Recommended=$recommendedValue"
            }
        }
        
        # Generate recommendations
        $nonCompliantCount = ($testResults.Compliance.Values | Where-Object { $_ -eq "Non-Compliant" }).Count
        $totalCount = $testResults.Compliance.Count
        
        if ($nonCompliantCount -eq 0) {
            $testResults.Recommendations += "All settings are compliant with $OptimizationLevel recommendations"
        } else {
            $testResults.Recommendations += "$nonCompliantCount out of $totalCount settings need adjustment"
            $testResults.Recommendations += "Run Set-SMBPerformanceOptimization -OptimizationLevel '$OptimizationLevel' to apply recommendations"
        }
        
        Write-Verbose "SMB performance settings test completed"
        return [PSCustomObject]$testResults
        
    } catch {
        Write-Error "Error testing SMB performance settings: $($_.Exception.Message)"
        return $null
    }
}

function Get-SMBPerformanceReport {
    <#
    .SYNOPSIS
        Generates a comprehensive SMB performance report
    
    .DESCRIPTION
        Creates a detailed report of SMB performance settings and recommendations
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER IncludeRecommendations
        Include optimization recommendations in the report
    
    .EXAMPLE
        Get-SMBPerformanceReport -OutputPath "C:\Reports\SMB-Performance.html"
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludeRecommendations
    )
    
    try {
        Write-Verbose "Generating SMB performance report..."
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            CurrentSettings = Get-SMBPerformanceSettings
            BasicCompliance = Test-SMBPerformanceSettings -OptimizationLevel "Basic"
            HighLatencyCompliance = Test-SMBPerformanceSettings -OptimizationLevel "HighLatency"
            EnterpriseCompliance = Test-SMBPerformanceSettings -OptimizationLevel "Enterprise"
            Summary = @{}
        }
        
        # Generate summary
        $report.Summary = @{
            TotalSettings = $report.CurrentSettings.RegistrySettings.Count
            BasicCompliant = ($report.BasicCompliance.Compliance.Values | Where-Object { $_ -eq "Compliant" }).Count
            HighLatencyCompliant = ($report.HighLatencyCompliance.Compliance.Values | Where-Object { $_ -eq "Compliant" }).Count
            EnterpriseCompliant = ($report.EnterpriseCompliance.Compliance.Values | Where-Object { $_ -eq "Compliant" }).Count
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "SMB Performance Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
h2 { color: #007acc; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.compliant { color: #28a745; font-weight: bold; }
.non-compliant { color: #dc3545; font-weight: bold; }
.recommendation { background-color: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
</style>
"@
            
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "SMB performance report saved to: $OutputPath" -ForegroundColor Green
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating SMB performance report: $($_.Exception.Message)"
        throw
    }
}

function Optimize-SMBForHighLatency {
    <#
    .SYNOPSIS
        Optimizes SMB settings specifically for high-latency networks
    
    .DESCRIPTION
        Applies Microsoft-recommended settings for high-latency networks like branch offices,
        cross-datacenter communication, home offices, and mobile broadband
    
    .EXAMPLE
        Optimize-SMBForHighLatency
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Optimizing SMB settings for high-latency networks..." -ForegroundColor Green
        
        # Apply high-latency optimization profile
        $result = Set-SMBPerformanceOptimization -OptimizationLevel "HighLatency"
        
        if ($result) {
            Write-Host "High-latency optimization completed successfully" -ForegroundColor Green
            Write-Host "Settings applied:" -ForegroundColor Yellow
            foreach ($setting in $result.SettingsApplied.GetEnumerator()) {
                Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor White
            }
            
            if ($result.Errors.Count -gt 0) {
                Write-Host "Errors encountered:" -ForegroundColor Red
                foreach ($error in $result.Errors) {
                    Write-Host "  $error" -ForegroundColor Red
                }
            }
        }
        
        return $result
        
    } catch {
        Write-Error "Error optimizing SMB for high-latency networks: $($_.Exception.Message)"
        throw
    }
}

function Optimize-SMBForEnterprise {
    <#
    .SYNOPSIS
        Optimizes SMB settings for enterprise environments
    
    .DESCRIPTION
        Applies Microsoft-recommended settings for enterprise file server environments
        with high throughput and multiple network interfaces
    
    .EXAMPLE
        Optimize-SMBForEnterprise
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Optimizing SMB settings for enterprise environment..." -ForegroundColor Green
        
        # Apply enterprise optimization profile
        $result = Set-SMBPerformanceOptimization -OptimizationLevel "Enterprise"
        
        if ($result) {
            Write-Host "Enterprise optimization completed successfully" -ForegroundColor Green
            Write-Host "Settings applied:" -ForegroundColor Yellow
            foreach ($setting in $result.SettingsApplied.GetEnumerator()) {
                Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor White
            }
            
            if ($result.RestartRequired) {
                Write-Host "Restart required for optimal performance" -ForegroundColor Yellow
            }
            
            if ($result.Errors.Count -gt 0) {
                Write-Host "Errors encountered:" -ForegroundColor Red
                foreach ($error in $result.Errors) {
                    Write-Host "  $error" -ForegroundColor Red
                }
            }
        }
        
        return $result
        
    } catch {
        Write-Error "Error optimizing SMB for enterprise environment: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Get-SMBPerformanceSettings',
    'Set-SMBPerformanceOptimization',
    'Test-SMBPerformanceSettings',
    'Get-SMBPerformanceReport',
    'Optimize-SMBForHighLatency',
    'Optimize-SMBForEnterprise'
)

# Module initialization
Write-Verbose "SMB-Performance module loaded successfully. Version: $ModuleVersion"
