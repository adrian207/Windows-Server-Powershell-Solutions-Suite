#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Rights Management Services Configuration Module

.DESCRIPTION
    This module provides functions for configuring AD RMS including cluster setup,
    service account configuration, and policy management.

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"
$ModuleName = "ADRMS-Configuration"

# Import required modules
try {
    Import-Module ADRMS-Core -ErrorAction Stop
} catch {
    Write-Warning "ADRMS-Core module not found. Some functions may not work properly."
}

#region Private Functions

function Test-ADRMSConfiguration {
    <#
    .SYNOPSIS
        Tests if AD RMS is properly configured
    
    .DESCRIPTION
        Validates AD RMS configuration including cluster settings,
        service account, and database configuration
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    $configStatus = @{
        ClusterConfigured = $false
        ServiceAccountConfigured = $false
        DatabaseConfigured = $false
        IISConfigured = $false
        Overall = 'Unknown'
    }
    
    try {
        # Check cluster configuration
        $regPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\Cluster"
        if (Test-Path $regPath) {
            $clusterUrl = Get-ItemProperty -Path $regPath -Name "ClusterURL" -ErrorAction SilentlyContinue
            $licensingUrl = Get-ItemProperty -Path $regPath -Name "LicensingURL" -ErrorAction SilentlyContinue
            
            if ($clusterUrl.ClusterURL -and $licensingUrl.LicensingURL) {
                $configStatus.ClusterConfigured = $true
                Write-Verbose "Cluster configuration found"
            }
        }
        
        # Check service account configuration
        $serviceAccountReg = "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
        if (Test-Path $serviceAccountReg) {
            $serviceAccount = Get-ItemProperty -Path $serviceAccountReg -Name "ServiceAccount" -ErrorAction SilentlyContinue
            if ($serviceAccount.ServiceAccount) {
                $configStatus.ServiceAccountConfigured = $true
                Write-Verbose "Service account configured"
            }
        }
        
        # Check database configuration
        $dbReg = "HKLM:\SOFTWARE\Microsoft\MSDRMS\Database"
        if (Test-Path $dbReg) {
            $dbServer = Get-ItemProperty -Path $dbReg -Name "DatabaseServer" -ErrorAction SilentlyContinue
            $dbName = Get-ItemProperty -Path $dbReg -Name "DatabaseName" -ErrorAction SilentlyContinue
            if ($dbServer.DatabaseServer -and $dbName.DatabaseName) {
                $configStatus.DatabaseConfigured = $true
                Write-Verbose "Database configuration found"
            }
        }
        
        # Check IIS configuration
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $rmsSite = Get-Website | Where-Object { $_.Name -like "*RMS*" }
            if ($rmsSite) {
                $configStatus.IISConfigured = $true
                Write-Verbose "IIS RMS site found"
            }
        } catch {
            Write-Verbose "Cannot check IIS configuration: $($_.Exception.Message)"
        }
        
        # Determine overall configuration status
        $configuredCount = ($configStatus.ClusterConfigured, $configStatus.ServiceAccountConfigured, 
                          $configStatus.DatabaseConfigured, $configStatus.IISConfigured | Where-Object { $_ }).Count
        
        if ($configuredCount -eq 4) {
            $configStatus.Overall = 'Fully Configured'
        } elseif ($configuredCount -gt 0) {
            $configStatus.Overall = 'Partially Configured'
        } else {
            $configStatus.Overall = 'Not Configured'
        }
        
        return [PSCustomObject]$configStatus
        
    } catch {
        Write-Error "Error testing AD RMS configuration: $($_.Exception.Message)"
        return $null
    }
}

function New-ADRMSCluster {
    <#
    .SYNOPSIS
        Creates a new AD RMS cluster configuration
    
    .DESCRIPTION
        Configures AD RMS cluster settings including URLs and certificates
    
    .PARAMETER ClusterUrl
        The cluster URL for AD RMS
    
    .PARAMETER LicensingUrl
        The licensing URL for AD RMS
    
    .PARAMETER DatabaseServer
        The database server name
    
    .PARAMETER DatabaseName
        The database name
    
    .PARAMETER ServiceAccount
        The service account for AD RMS
    
    .PARAMETER ServiceAccountPassword
        The password for the service account
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$LicensingUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$DatabaseServer,
        
        [Parameter(Mandatory = $true)]
        [string]$DatabaseName,
        
        [Parameter(Mandatory = $true)]
        [string]$ServiceAccount,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$ServiceAccountPassword
    )
    
    try {
        Write-Host "Creating AD RMS cluster configuration..." -ForegroundColor Green
        
        # Create cluster registry entries
        $clusterRegPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\Cluster"
        if (-not (Test-Path $clusterRegPath)) {
            New-Item -Path $clusterRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $clusterRegPath -Name "ClusterURL" -Value $ClusterUrl
        Set-ItemProperty -Path $clusterRegPath -Name "LicensingURL" -Value $LicensingUrl
        
        Write-Host "Cluster URLs configured" -ForegroundColor Green
        
        # Create database registry entries
        $dbRegPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\Database"
        if (-not (Test-Path $dbRegPath)) {
            New-Item -Path $dbRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $dbRegPath -Name "DatabaseServer" -Value $DatabaseServer
        Set-ItemProperty -Path $dbRegPath -Name "DatabaseName" -Value $DatabaseName
        
        Write-Host "Database configuration set" -ForegroundColor Green
        
        # Configure service account
        $serviceAccountRegPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
        if (-not (Test-Path $serviceAccountRegPath)) {
            New-Item -Path $serviceAccountRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $serviceAccountRegPath -Name "ServiceAccount" -Value $ServiceAccount
        
        # Convert secure string to plain text for registry (not recommended for production)
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
        Set-ItemProperty -Path $serviceAccountRegPath -Name "ServiceAccountPassword" -Value $plainPassword
        
        Write-Host "Service account configured" -ForegroundColor Green
        
        Write-Host "AD RMS cluster configuration completed successfully" -ForegroundColor Green
        
    } catch {
        Write-Error "Error creating AD RMS cluster: $($_.Exception.Message)"
        throw
    }
}

#endregion

#region Public Functions

function Initialize-ADRMSConfiguration {
    <#
    .SYNOPSIS
        Initializes AD RMS configuration with default settings
    
    .DESCRIPTION
        Sets up AD RMS with default configuration values
    
    .PARAMETER DomainName
        The domain name for the AD RMS cluster
    
    .PARAMETER DatabaseServer
        The database server (defaults to localhost)
    
    .PARAMETER ServiceAccount
        The service account (defaults to RMS_Service)
    
    .PARAMETER ServiceAccountPassword
        The password for the service account
    
    .EXAMPLE
        Initialize-ADRMSConfiguration -DomainName "contoso.com" -ServiceAccountPassword $securePassword
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        
        [string]$DatabaseServer = "localhost",
        
        [string]$ServiceAccount = "RMS_Service",
        
        [Parameter(Mandatory = $true)]
        [SecureString]$ServiceAccountPassword
    )
    
    try {
        Write-Host "Initializing AD RMS configuration..." -ForegroundColor Green
        
        # Generate cluster URLs
        $computerName = $env:COMPUTERNAME
        $clusterUrl = "https://$computerName.$DomainName/_wmcs"
        $licensingUrl = "https://$computerName.$DomainName/_wmcs/licensing"
        
        # Create cluster configuration
        New-ADRMSCluster -ClusterUrl $clusterUrl -LicensingUrl $licensingUrl -DatabaseServer $DatabaseServer -DatabaseName "DRMS" -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword
        
        Write-Host "AD RMS configuration initialized successfully" -ForegroundColor Green
        
    } catch {
        Write-Error "Error initializing AD RMS configuration: $($_.Exception.Message)"
        throw
    }
}

function Set-ADRMSServiceAccount {
    <#
    .SYNOPSIS
        Configures the AD RMS service account
    
    .DESCRIPTION
        Sets up the service account for AD RMS operations
    
    .PARAMETER ServiceAccount
        The service account name
    
    .PARAMETER ServiceAccountPassword
        The password for the service account
    
    .EXAMPLE
        Set-ADRMSServiceAccount -ServiceAccount "RMS_Service" -ServiceAccountPassword $securePassword
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceAccount,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$ServiceAccountPassword
    )
    
    try {
        Write-Host "Configuring AD RMS service account..." -ForegroundColor Green
        
        # Create service account registry entries
        $serviceAccountRegPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
        if (-not (Test-Path $serviceAccountRegPath)) {
            New-Item -Path $serviceAccountRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $serviceAccountRegPath -Name "ServiceAccount" -Value $ServiceAccount
        
        # Convert secure string to plain text for registry (not recommended for production)
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
        Set-ItemProperty -Path $serviceAccountRegPath -Name "ServiceAccountPassword" -Value $plainPassword
        
        Write-Host "Service account configured: $ServiceAccount" -ForegroundColor Green
        
    } catch {
        Write-Error "Error configuring service account: $($_.Exception.Message)"
        throw
    }
}

function Set-ADRMSDatabase {
    <#
    .SYNOPSIS
        Configures the AD RMS database settings
    
    .DESCRIPTION
        Sets up database configuration for AD RMS
    
    .PARAMETER DatabaseServer
        The database server name
    
    .PARAMETER DatabaseName
        The database name
    
    .PARAMETER DatabaseUser
        The database user account
    
    .PARAMETER DatabasePassword
        The password for the database user
    
    .EXAMPLE
        Set-ADRMSDatabase -DatabaseServer "SQL01" -DatabaseName "DRMS" -DatabaseUser "RMS_DBUser" -DatabasePassword $securePassword
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatabaseServer,
        
        [Parameter(Mandatory = $true)]
        [string]$DatabaseName,
        
        [string]$DatabaseUser,
        
        [SecureString]$DatabasePassword
    )
    
    try {
        Write-Host "Configuring AD RMS database..." -ForegroundColor Green
        
        # Create database registry entries
        $dbRegPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\Database"
        if (-not (Test-Path $dbRegPath)) {
            New-Item -Path $dbRegPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $dbRegPath -Name "DatabaseServer" -Value $DatabaseServer
        Set-ItemProperty -Path $dbRegPath -Name "DatabaseName" -Value $DatabaseName
        
        if ($DatabaseUser) {
            Set-ItemProperty -Path $dbRegPath -Name "DatabaseUser" -Value $DatabaseUser
        }
        
        if ($DatabasePassword) {
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DatabasePassword))
            Set-ItemProperty -Path $dbRegPath -Name "DatabasePassword" -Value $plainPassword
        }
        
        Write-Host "Database configured - Server: $DatabaseServer, Database: $DatabaseName" -ForegroundColor Green
        
    } catch {
        Write-Error "Error configuring database: $($_.Exception.Message)"
        throw
    }
}

function Get-ADRMSConfigurationStatus {
    <#
    .SYNOPSIS
        Gets the current AD RMS configuration status
    
    .DESCRIPTION
        Returns detailed information about AD RMS configuration
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Retrieving AD RMS configuration status..." -ForegroundColor Green
        
        $configStatus = Test-ADRMSConfiguration
        $currentConfig = Get-ADRMSConfiguration
        
        $status = @{
            ConfigurationStatus = $configStatus
            CurrentConfiguration = $currentConfig
            Timestamp = Get-Date
        }
        
        return [PSCustomObject]$status
        
    } catch {
        Write-Error "Error getting configuration status: $($_.Exception.Message)"
        throw
    }
}

function Reset-ADRMSConfiguration {
    <#
    .SYNOPSIS
        Resets AD RMS configuration to default state
    
    .DESCRIPTION
        Removes AD RMS configuration settings and returns to unconfigured state
    
    .PARAMETER Confirm
        Confirms the reset operation
    
    .EXAMPLE
        Reset-ADRMSConfiguration -Confirm
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    try {
        if ($PSCmdlet.ShouldProcess("AD RMS Configuration", "Reset")) {
            Write-Host "Resetting AD RMS configuration..." -ForegroundColor Yellow
            
            # Remove registry entries
            $regPaths = @(
                "HKLM:\SOFTWARE\Microsoft\MSDRMS\Cluster",
                "HKLM:\SOFTWARE\Microsoft\MSDRMS\Database",
                "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
            )
            
            foreach ($regPath in $regPaths) {
                if (Test-Path $regPath) {
                    Remove-Item -Path $regPath -Recurse -Force
                    Write-Host "Removed registry path: $regPath" -ForegroundColor Green
                }
            }
            
            Write-Host "AD RMS configuration reset completed" -ForegroundColor Green
        }
        
    } catch {
        Write-Error "Error resetting AD RMS configuration: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Initialize-ADRMSConfiguration',
    'Set-ADRMSServiceAccount',
    'Set-ADRMSDatabase',
    'Get-ADRMSConfigurationStatus',
    'Reset-ADRMSConfiguration'
)

# Module initialization
Write-Verbose "ADRMS-Configuration module loaded successfully. Version: $ModuleVersion"
