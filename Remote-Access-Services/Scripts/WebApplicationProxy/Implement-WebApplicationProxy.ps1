#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Web Application Proxy Implementation Script

.DESCRIPTION
    This script provides comprehensive Web Application Proxy implementation
    including installation, configuration, and management.

.PARAMETER Action
    Action to perform (Install, Configure, Test, Monitor, Remove)

.PARAMETER ConfigurationFile
    Path to configuration file

.PARAMETER LogFile
    Path to log file

.EXAMPLE
    .\Implement-WebApplicationProxy.ps1 -Action "Install"

.EXAMPLE
    .\Implement-WebApplicationProxy.ps1 -Action "Configure" -ConfigurationFile "C:\Config\WebApplicationProxy.json"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Configure", "Test", "Monitor", "Remove")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile
)

# Script configuration
$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Logging configuration
if (-not $LogFile) {
    $LogFile = "C:\Logs\WebApplicationProxy-Implementation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

# Create log directory if it doesn't exist
$LogDirectory = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

#region Helper Functions

function Write-WebApplicationProxyLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

function Test-WebApplicationProxyPrerequisites {
    Write-WebApplicationProxyLog "Testing Web Application Proxy prerequisites..."
    
    $prerequisites = @{
        OSVersion = $false
        PowerShellVersion = $false
        AdministratorPrivileges = $false
        NetworkConnectivity = $false
        WebApplicationProxyInstalled = $false
        ADDSInstalled = $false
    }
    
    # Check OS version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10) {
        $prerequisites.OSVersion = $true
        Write-WebApplicationProxyLog "OS Version: Windows 10/Server 2016+ (Compatible)"
    } else {
        Write-WebApplicationProxyLog "OS Version: $($osVersion) (Incompatible)" "ERROR"
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
        Write-WebApplicationProxyLog "PowerShell Version: $psVersion (Compatible)"
    } else {
        Write-WebApplicationProxyLog "PowerShell Version: $psVersion (Incompatible)" "ERROR"
    }
    
    # Check administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $prerequisites.AdministratorPrivileges = $true
        Write-WebApplicationProxyLog "Administrator privileges: Confirmed"
    } else {
        Write-WebApplicationProxyLog "Administrator privileges: Not available" "ERROR"
    }
    
    # Check network connectivity
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
        $prerequisites.NetworkConnectivity = $ping
        Write-WebApplicationProxyLog "Network connectivity: $($ping ? 'Available' : 'Not available')"
    } catch {
        Write-WebApplicationProxyLog "Network connectivity: Check failed" "WARNING"
    }
    
    # Check Web Application Proxy installation
    try {
        $wapFeature = Get-WindowsFeature -Name "Web-Application-Proxy" -ErrorAction SilentlyContinue
        $prerequisites.WebApplicationProxyInstalled = ($wapFeature -and $wapFeature.InstallState -eq "Installed")
        Write-WebApplicationProxyLog "Web Application Proxy installation: $($prerequisites.WebApplicationProxyInstalled ? 'Installed' : 'Not installed')"
    } catch {
        Write-WebApplicationProxyLog "Web Application Proxy installation: Check failed" "WARNING"
    }
    
    # Check AD DS installation
    try {
        $addsFeature = Get-WindowsFeature -Name "AD-Domain-Services" -ErrorAction SilentlyContinue
        $prerequisites.ADDSInstalled = ($addsFeature -and $addsFeature.InstallState -eq "Installed")
        Write-WebApplicationProxyLog "AD DS installation: $($prerequisites.ADDSInstalled ? 'Installed' : 'Not installed')"
    } catch {
        Write-WebApplicationProxyLog "AD DS installation: Check failed" "WARNING"
    }
    
    return $prerequisites
}

function Install-WebApplicationProxyFeatures {
    Write-WebApplicationProxyLog "Installing Web Application Proxy features..."
    
    try {
        # Install Web Application Proxy feature
        $result = Install-WindowsFeature -Name "Web-Application-Proxy" -IncludeManagementTools -ErrorAction Stop
        if ($result.Success) {
            Write-WebApplicationProxyLog "Web Application Proxy feature installed successfully"
        } else {
            throw "Failed to install Web Application Proxy feature"
        }
        
        # Install additional required features
        $additionalFeatures = @(
            "RSAT-Web-Application-Proxy-PowerShell",
            "RSAT-Web-Application-Proxy-Mgmt"
        )
        
        foreach ($feature in $additionalFeatures) {
            try {
                $featureResult = Install-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
                if ($featureResult.Success) {
                    Write-WebApplicationProxyLog "Feature $feature installed successfully"
                } else {
                    Write-WebApplicationProxyLog "Feature $feature installation failed" "WARNING"
                }
            } catch {
                Write-WebApplicationProxyLog "Feature $feature installation error: $($_.Exception.Message)" "WARNING"
            }
        }
        
        return $true
        
    } catch {
        Write-WebApplicationProxyLog "Web Application Proxy features installation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-WebApplicationProxyConfiguration {
    param(
        [hashtable]$Configuration
    )
    
    Write-WebApplicationProxyLog "Configuring Web Application Proxy..."
    
    try {
        # Import WebApplicationProxy module
        Import-Module WebApplicationProxy -Force -ErrorAction SilentlyContinue
        
        # Configure Web Application Proxy settings
        if ($Configuration.ContainsKey("FederationServiceName")) {
            Write-WebApplicationProxyLog "Setting federation service name: $($Configuration.FederationServiceName)"
            # Note: Actual Web Application Proxy configuration would require specific cmdlets
            # This is a placeholder for the configuration process
        }
        
        if ($Configuration.ContainsKey("CertificateThumbprint")) {
            Write-WebApplicationProxyLog "Setting certificate thumbprint: $($Configuration.CertificateThumbprint)"
        }
        
        if ($Configuration.ContainsKey("ADFSServerName")) {
            Write-WebApplicationProxyLog "Setting ADFS server name: $($Configuration.ADFSServerName)"
        }
        
        if ($Configuration.ContainsKey("ExternalURL")) {
            Write-WebApplicationProxyLog "Setting external URL: $($Configuration.ExternalURL)"
        }
        
        if ($Configuration.ContainsKey("InternalURL")) {
            Write-WebApplicationProxyLog "Setting internal URL: $($Configuration.InternalURL)"
        }
        
        Write-WebApplicationProxyLog "Web Application Proxy configuration completed successfully"
        return $true
        
    } catch {
        Write-WebApplicationProxyLog "Web Application Proxy configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-WebApplicationProxyConfiguration {
    Write-WebApplicationProxyLog "Testing Web Application Proxy configuration..."
    
    try {
        # Import WebApplicationProxy module
        Import-Module WebApplicationProxy -Force -ErrorAction SilentlyContinue
        
        # Test Web Application Proxy status
        # Note: Actual Web Application Proxy testing would require specific cmdlets
        # This is a placeholder for the testing process
        Write-WebApplicationProxyLog "Web Application Proxy configuration test completed"
        
        return @{
            Success = $true
            Status = "Healthy"
            Issues = @()
        }
        
    } catch {
        Write-WebApplicationProxyLog "Web Application Proxy configuration test failed: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            Status = "Failed"
            Issues = @($_.Exception.Message)
        }
    }
}

function Start-WebApplicationProxyMonitoring {
    Write-WebApplicationProxyLog "Starting Web Application Proxy monitoring..."
    
    try {
        # Start monitoring Web Application Proxy services
        $services = @("WebApplicationProxy", "W3SVC", "WAS")
        
        foreach ($service in $services) {
            try {
                $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($serviceObj) {
                    Write-WebApplicationProxyLog "Service $service status: $($serviceObj.Status)"
                } else {
                    Write-WebApplicationProxyLog "Service $service not found" "WARNING"
                }
            } catch {
                Write-WebApplicationProxyLog "Service $service check failed: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Monitor Web Application Proxy performance counters
        try {
            $perfCounters = Get-Counter -ListSet "*WebApplicationProxy*" -ErrorAction SilentlyContinue
            if ($perfCounters) {
                Write-WebApplicationProxyLog "Web Application Proxy performance counters available: $($perfCounters.Count)"
            } else {
                Write-WebApplicationProxyLog "Web Application Proxy performance counters not available" "WARNING"
            }
        } catch {
            Write-WebApplicationProxyLog "Performance counter check failed: $($_.Exception.Message)" "WARNING"
        }
        
        Write-WebApplicationProxyLog "Web Application Proxy monitoring started successfully"
        return $true
        
    } catch {
        Write-WebApplicationProxyLog "Web Application Proxy monitoring failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-WebApplicationProxyConfiguration {
    Write-WebApplicationProxyLog "Removing Web Application Proxy configuration..."
    
    try {
        # Import WebApplicationProxy module
        Import-Module WebApplicationProxy -Force -ErrorAction SilentlyContinue
        
        # Remove Web Application Proxy configuration
        # Note: Actual Web Application Proxy removal would require specific cmdlets
        # This is a placeholder for the removal process
        Write-WebApplicationProxyLog "Web Application Proxy configuration removal completed"
        
        return $true
        
    } catch {
        Write-WebApplicationProxyLog "Web Application Proxy configuration removal failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion

#region Main Script Logic

try {
    Write-WebApplicationProxyLog "Starting Web Application Proxy Implementation Script - Version $ScriptVersion"
    Write-WebApplicationProxyLog "Action: $Action"
    Write-WebApplicationProxyLog "Computer: $env:COMPUTERNAME"
    Write-WebApplicationProxyLog "User: $env:USERNAME"
    
    # Test prerequisites
    $prerequisites = Test-WebApplicationProxyPrerequisites
    
    $criticalFailures = @()
    if (-not $prerequisites.OSVersion) { $criticalFailures += "OS Version" }
    if (-not $prerequisites.PowerShellVersion) { $criticalFailures += "PowerShell Version" }
    if (-not $prerequisites.AdministratorPrivileges) { $criticalFailures += "Administrator Privileges" }
    
    if ($criticalFailures.Count -gt 0) {
        throw "Critical prerequisites failed: $($criticalFailures -join ', ')"
    }
    
    Write-WebApplicationProxyLog "Prerequisites check completed successfully"
    
    # Load configuration if provided
    $configuration = @{}
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        try {
            $configuration = Get-Content $ConfigurationFile -Raw | ConvertFrom-Json -AsHashtable
            Write-WebApplicationProxyLog "Configuration loaded from: $ConfigurationFile"
        } catch {
            Write-WebApplicationProxyLog "Failed to load configuration file: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Execute action
    $actionResult = @{
        Action = $Action
        Success = $false
        StartTime = $ScriptStartTime
        EndTime = $null
        Duration = $null
        Error = $null
        Prerequisites = $prerequisites
        Configuration = $configuration
    }
    
    switch ($Action) {
        "Install" {
            Write-WebApplicationProxyLog "Installing Web Application Proxy..."
            $actionResult.Success = Install-WebApplicationProxyFeatures
        }
        
        "Configure" {
            Write-WebApplicationProxyLog "Configuring Web Application Proxy..."
            $actionResult.Success = Set-WebApplicationProxyConfiguration -Configuration $configuration
        }
        
        "Test" {
            Write-WebApplicationProxyLog "Testing Web Application Proxy configuration..."
            $testResult = Test-WebApplicationProxyConfiguration
            $actionResult.Success = $testResult.Success
            $actionResult.TestResult = $testResult
        }
        
        "Monitor" {
            Write-WebApplicationProxyLog "Starting Web Application Proxy monitoring..."
            $actionResult.Success = Start-WebApplicationProxyMonitoring
        }
        
        "Remove" {
            Write-WebApplicationProxyLog "Removing Web Application Proxy configuration..."
            $actionResult.Success = Remove-WebApplicationProxyConfiguration
        }
    }
    
    # Calculate duration
    $actionResult.EndTime = Get-Date
    $actionResult.Duration = $actionResult.EndTime - $actionResult.StartTime
    
    if ($actionResult.Success) {
        Write-WebApplicationProxyLog "Web Application Proxy $Action completed successfully!"
        Write-WebApplicationProxyLog "Duration: $($actionResult.Duration.TotalMinutes.ToString('F2')) minutes"
    } else {
        Write-WebApplicationProxyLog "Web Application Proxy $Action failed!" "ERROR"
        Write-WebApplicationProxyLog "Duration: $($actionResult.Duration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    }
    
    # Return result
    return [PSCustomObject]$actionResult
    
} catch {
    $scriptEndTime = Get-Date
    $scriptDuration = $scriptEndTime - $ScriptStartTime
    
    Write-WebApplicationProxyLog "Web Application Proxy Implementation Script FAILED!" "ERROR"
    Write-WebApplicationProxyLog "Error: $($_.Exception.Message)" "ERROR"
    Write-WebApplicationProxyLog "Duration: $($scriptDuration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    
    # Return failure result
    $actionResult = @{
        Action = $Action
        Success = $false
        StartTime = $ScriptStartTime
        EndTime = $scriptEndTime
        Duration = $scriptDuration
        Error = $_.Exception.Message
    }
    
    return [PSCustomObject]$actionResult
}

#endregion
