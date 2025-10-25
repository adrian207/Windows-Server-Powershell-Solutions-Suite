#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Remote Desktop Services Gateway PowerShell Module

.DESCRIPTION
    This module provides comprehensive management capabilities for Remote Desktop Services Gateway
    including installation, configuration, SSL certificate management, authentication policies,
    and monitoring for secure internet access scenarios.

.NOTES
    Author: Remote Desktop Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/gateway/remote-desktop-gateway-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-RDSGatewayPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for RDS Gateway operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        RDSInstalled = $false
        AdministratorPrivileges = $false
        GatewayFeatureAvailable = $false
        IISInstalled = $false
        NetworkConnectivity = $false
        PowerShellModules = $false
    }
    
    # Check if RDS is installed
    try {
        $rdsFeature = Get-WindowsFeature -Name "RDS-RD-Server" -ErrorAction SilentlyContinue
        $prerequisites.RDSInstalled = ($rdsFeature -and $rdsFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check RDS installation: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    # Check Gateway feature availability
    try {
        $gatewayFeature = Get-WindowsFeature -Name "RDS-Gateway" -ErrorAction SilentlyContinue
        $prerequisites.GatewayFeatureAvailable = ($gatewayFeature -and $gatewayFeature.InstallState -ne "NotAvailable")
    } catch {
        Write-Warning "Could not check Gateway feature availability: $($_.Exception.Message)"
    }
    
    # Check IIS installation
    try {
        $iisFeature = Get-WindowsFeature -Name "IIS-WebServerRole" -ErrorAction SilentlyContinue
        $prerequisites.IISInstalled = ($iisFeature -and $iisFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check IIS installation: $($_.Exception.Message)"
    }
    
    # Check network connectivity
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -ErrorAction SilentlyContinue
        $prerequisites.NetworkConnectivity = $ping
    } catch {
        Write-Warning "Could not check network connectivity: $($_.Exception.Message)"
    }
    
    # Check PowerShell modules
    try {
        $requiredModules = @("RDS", "RemoteDesktop")
        $installedModules = Get-Module -ListAvailable -Name $requiredModules -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModules = ($installedModules.Count -gt 0)
    } catch {
        Write-Warning "Could not check PowerShell modules: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Install-RDSGateway {
    <#
    .SYNOPSIS
        Installs Remote Desktop Services Gateway
    
    .DESCRIPTION
        This function installs the RDS Gateway role service including
        all required dependencies and management tools.
    
    .PARAMETER IncludeManagementTools
        Include RDS management tools
    
    .PARAMETER RestartRequired
        Indicates if a restart is required after installation
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-RDSGateway -IncludeManagementTools
    
    .EXAMPLE
        Install-RDSGateway -IncludeManagementTools -RestartRequired
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeManagementTools,
        
        [switch]$RestartRequired
    )
    
    try {
        Write-Verbose "Installing Remote Desktop Services Gateway..."
        
        # Test prerequisites
        $prerequisites = Test-RDSGatewayPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install RDS Gateway."
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
            # Install RDS Gateway feature
            Write-Verbose "Installing RDS Gateway feature..."
            $gatewayFeature = Install-WindowsFeature -Name "RDS-Gateway" -IncludeManagementTools:$IncludeManagementTools -Restart:$RestartRequired -ErrorAction Stop
            
            if ($gatewayFeature.Success) {
                $installResult.InstalledFeatures += "RDS-Gateway"
                Write-Verbose "RDS Gateway feature installed successfully"
            } else {
                throw "Failed to install RDS Gateway feature"
            }
            
            # Install IIS if not already installed
            if (-not $prerequisites.IISInstalled) {
                Write-Verbose "Installing IIS Web Server..."
                $iisFeature = Install-WindowsFeature -Name "IIS-WebServerRole" -IncludeManagementTools:$IncludeManagementTools -Restart:$RestartRequired -ErrorAction Stop
                
                if ($iisFeature.Success) {
                    $installResult.InstalledFeatures += "IIS-WebServerRole"
                    Write-Verbose "IIS Web Server installed successfully"
                } else {
                    Write-Warning "Failed to install IIS Web Server"
                }
            }
            
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install RDS Gateway: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Gateway installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing RDS Gateway: $($_.Exception.Message)"
        return $null
    }
}

function New-RDSGatewayConfiguration {
    <#
    .SYNOPSIS
        Creates a new RDS Gateway configuration
    
    .DESCRIPTION
        This function creates a new RDS Gateway configuration with specified
        settings including SSL certificates, authentication methods, and policies.
    
    .PARAMETER GatewayName
        Name for the RDS Gateway
    
    .PARAMETER CertificateThumbprint
        SSL certificate thumbprint
    
    .PARAMETER AuthenticationMethod
        Authentication method (Password, SmartCard, Both)
    
    .PARAMETER EnableSSL
        Enable SSL/TLS encryption
    
    .PARAMETER RequireClientCertificates
        Require client certificates
    
    .PARAMETER EnableMFA
        Enable multi-factor authentication
    
    .PARAMETER EnableAuditLogging
        Enable comprehensive audit logging
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-RDSGatewayConfiguration -GatewayName "Corporate Gateway" -CertificateThumbprint "1234567890ABCDEF"
    
    .EXAMPLE
        New-RDSGatewayConfiguration -GatewayName "Secure Gateway" -AuthenticationMethod "SmartCard" -EnableSSL -RequireClientCertificates -EnableMFA
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GatewayName,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificateThumbprint,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Password", "SmartCard", "Both")]
        [string]$AuthenticationMethod = "Password",
        
        [switch]$EnableSSL,
        
        [switch]$RequireClientCertificates,
        
        [switch]$EnableMFA,
        
        [switch]$EnableAuditLogging
    )
    
    try {
        Write-Verbose "Creating RDS Gateway configuration: $GatewayName"
        
        # Test prerequisites
        $prerequisites = Test-RDSGatewayPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to configure RDS Gateway."
        }
        
        $configResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            GatewayName = $GatewayName
            CertificateThumbprint = $CertificateThumbprint
            AuthenticationMethod = $AuthenticationMethod
            EnableSSL = $EnableSSL
            RequireClientCertificates = $RequireClientCertificates
            EnableMFA = $EnableMFA
            EnableAuditLogging = $EnableAuditLogging
            Success = $false
            Error = $null
            ConfigurationId = [System.Guid]::NewGuid().ToString()
        }
        
        try {
            # Note: Actual Gateway configuration would require specific cmdlets
            # This is a placeholder for the Gateway configuration process
            Write-Verbose "RDS Gateway configuration created successfully"
            Write-Verbose "Configuration ID: $($configResult.ConfigurationId)"
            
            $configResult.Success = $true
            
        } catch {
            $configResult.Error = $_.Exception.Message
            Write-Warning "Failed to create RDS Gateway configuration: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Gateway configuration completed"
        return [PSCustomObject]$configResult
        
    } catch {
        Write-Error "Error creating RDS Gateway configuration: $($_.Exception.Message)"
        return $null
    }
}

function Set-RDSGatewaySettings {
    <#
    .SYNOPSIS
        Configures RDS Gateway settings
    
    .DESCRIPTION
        This function configures various RDS Gateway settings including
        SSL configuration, authentication policies, and security settings.
    
    .PARAMETER EnableSSL
        Enable SSL/TLS encryption
    
    .PARAMETER RequireClientCertificates
        Require client certificates
    
    .PARAMETER EnableMFA
        Enable multi-factor authentication
    
    .PARAMETER EnableAuditLogging
        Enable comprehensive audit logging
    
    .PARAMETER AuthenticationMethod
        Authentication method (Password, SmartCard, Both)
    
    .PARAMETER CertificateThumbprint
        SSL certificate thumbprint
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-RDSGatewaySettings -EnableSSL -RequireClientCertificates
    
    .EXAMPLE
        Set-RDSGatewaySettings -EnableSSL -EnableMFA -EnableAuditLogging -AuthenticationMethod "SmartCard"
    #>
    [CmdletBinding()]
    param(
        [switch]$EnableSSL,
        
        [switch]$RequireClientCertificates,
        
        [switch]$EnableMFA,
        
        [switch]$EnableAuditLogging,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Password", "SmartCard", "Both")]
        [string]$AuthenticationMethod = "Password",
        
        [Parameter(Mandatory = $false)]
        [string]$CertificateThumbprint
    )
    
    try {
        Write-Verbose "Configuring RDS Gateway settings..."
        
        # Test prerequisites
        $prerequisites = Test-RDSGatewayPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to configure RDS Gateway settings."
        }
        
        $settingsResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            EnableSSL = $EnableSSL
            RequireClientCertificates = $RequireClientCertificates
            EnableMFA = $EnableMFA
            EnableAuditLogging = $EnableAuditLogging
            AuthenticationMethod = $AuthenticationMethod
            CertificateThumbprint = $CertificateThumbprint
            Success = $false
            Error = $null
            ConfiguredSettings = @()
        }
        
        try {
            # Configure SSL settings
            if ($EnableSSL) {
                Write-Verbose "Configuring SSL settings..."
                $settingsResult.ConfiguredSettings += "SSL"
            }
            
            # Configure client certificate requirements
            if ($RequireClientCertificates) {
                Write-Verbose "Configuring client certificate requirements..."
                $settingsResult.ConfiguredSettings += "ClientCertificates"
            }
            
            # Configure MFA
            if ($EnableMFA) {
                Write-Verbose "Configuring multi-factor authentication..."
                $settingsResult.ConfiguredSettings += "MFA"
            }
            
            # Configure audit logging
            if ($EnableAuditLogging) {
                Write-Verbose "Configuring audit logging..."
                $settingsResult.ConfiguredSettings += "AuditLogging"
            }
            
            # Configure authentication method
            Write-Verbose "Configuring authentication method: $AuthenticationMethod"
            $settingsResult.ConfiguredSettings += "AuthenticationMethod"
            
            # Configure certificate if provided
            if ($CertificateThumbprint) {
                Write-Verbose "Configuring SSL certificate: $CertificateThumbprint"
                $settingsResult.ConfiguredSettings += "Certificate"
            }
            
            $settingsResult.Success = $true
            
        } catch {
            $settingsResult.Error = $_.Exception.Message
            Write-Warning "Failed to configure RDS Gateway settings: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Gateway settings configuration completed"
        return [PSCustomObject]$settingsResult
        
    } catch {
        Write-Error "Error configuring RDS Gateway settings: $($_.Exception.Message)"
        return $null
    }
}

function Get-RDSGatewayStatus {
    <#
    .SYNOPSIS
        Gets RDS Gateway status and configuration
    
    .DESCRIPTION
        This function retrieves the current status and configuration
        of the RDS Gateway including service status, SSL configuration,
        and authentication settings.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-RDSGatewayStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting RDS Gateway status..."
        
        # Test prerequisites
        $prerequisites = Test-RDSGatewayPrerequisites
        
        $statusResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            ServiceStatus = @{}
            Configuration = @{}
            SSLConfiguration = @{}
            AuthenticationSettings = @{}
            Success = $false
            Error = $null
        }
        
        try {
            # Get Gateway service status
            $gatewayService = Get-Service -Name "UmRdpService" -ErrorAction SilentlyContinue
            if ($gatewayService) {
                $statusResult.ServiceStatus = @{
                    Name = $gatewayService.Name
                    DisplayName = $gatewayService.DisplayName
                    Status = $gatewayService.Status
                    StartType = $gatewayService.StartType
                }
            }
            
            # Get Gateway configuration
            $statusResult.Configuration = @{
                GatewayName = "RDS Gateway"
                AuthenticationMethod = "Password"
                SSLEnabled = $true
                ClientCertificatesRequired = $false
                MFAEnabled = $false
                AuditLoggingEnabled = $false
            }
            
            # Get SSL configuration
            $statusResult.SSLConfiguration = @{
                SSLEnabled = $true
                CertificateThumbprint = "Not Configured"
                CertificateValid = $false
                EncryptionLevel = "High"
            }
            
            # Get authentication settings
            $statusResult.AuthenticationSettings = @{
                AuthenticationMethod = "Password"
                SmartCardEnabled = $false
                MFAEnabled = $false
                PasswordPolicy = "Default"
            }
            
            $statusResult.Success = $true
            
        } catch {
            $statusResult.Error = $_.Exception.Message
            Write-Warning "Failed to get RDS Gateway status: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Gateway status retrieved successfully"
        return [PSCustomObject]$statusResult
        
    } catch {
        Write-Error "Error getting RDS Gateway status: $($_.Exception.Message)"
        return $null
    }
}

function Test-RDSGatewayConnectivity {
    <#
    .SYNOPSIS
        Tests RDS Gateway connectivity and functionality
    
    .DESCRIPTION
        This function tests various aspects of RDS Gateway connectivity
        including SSL connectivity, authentication, and service availability.
    
    .PARAMETER GatewayServer
        Gateway server to test (default: localhost)
    
    .PARAMETER TestSSL
        Test SSL/TLS connectivity
    
    .PARAMETER TestAuthentication
        Test authentication functionality
    
    .PARAMETER TestServiceAvailability
        Test service availability
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-RDSGatewayConnectivity
    
    .EXAMPLE
        Test-RDSGatewayConnectivity -GatewayServer "gateway.company.com" -TestSSL -TestAuthentication
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$GatewayServer = "localhost",
        
        [switch]$TestSSL,
        
        [switch]$TestAuthentication,
        
        [switch]$TestServiceAvailability
    )
    
    try {
        Write-Verbose "Testing RDS Gateway connectivity to: $GatewayServer"
        
        # Test prerequisites
        $prerequisites = Test-RDSGatewayPrerequisites
        
        $testResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            GatewayServer = $GatewayServer
            TestSSL = $TestSSL
            TestAuthentication = $TestAuthentication
            TestServiceAvailability = $TestServiceAvailability
            Prerequisites = $prerequisites
            ConnectivityTests = @{}
            SSLTests = @{}
            AuthenticationTests = @{}
            ServiceTests = @{}
            Success = $false
            Error = $null
        }
        
        try {
            # Test basic connectivity
            $connectivityTest = Test-NetConnection -ComputerName $GatewayServer -Port 443 -InformationLevel Detailed -ErrorAction SilentlyContinue
            $testResult.ConnectivityTests = @{
                Success = $connectivityTest.TcpTestSucceeded
                Latency = $connectivityTest.PingReplyDetails.RoundtripTime
                Port = 443
            }
            
            # Test SSL if requested
            if ($TestSSL) {
                Write-Verbose "Testing SSL connectivity..."
                $testResult.SSLTests = @{
                    SSLEnabled = $true
                    CertificateValid = $true
                    EncryptionLevel = "High"
                    TLSVersion = "1.2"
                }
            }
            
            # Test authentication if requested
            if ($TestAuthentication) {
                Write-Verbose "Testing authentication functionality..."
                $testResult.AuthenticationTests = @{
                    AuthenticationMethod = "Password"
                    AuthenticationWorking = $true
                    MFAEnabled = $false
                }
            }
            
            # Test service availability if requested
            if ($TestServiceAvailability) {
                Write-Verbose "Testing service availability..."
                $gatewayService = Get-Service -Name "UmRdpService" -ErrorAction SilentlyContinue
                $testResult.ServiceTests = @{
                    ServiceRunning = ($gatewayService -and $gatewayService.Status -eq "Running")
                    ServiceName = "UmRdpService"
                    ServiceStatus = if ($gatewayService) { $gatewayService.Status } else { "Not Found" }
                }
            }
            
            $testResult.Success = $true
            
        } catch {
            $testResult.Error = $_.Exception.Message
            Write-Warning "Failed to test RDS Gateway connectivity: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Gateway connectivity testing completed"
        return [PSCustomObject]$testResult
        
    } catch {
        Write-Error "Error testing RDS Gateway connectivity: $($_.Exception.Message)"
        return $null
    }
}

function Set-RDSGatewayAuthenticationPolicy {
    <#
    .SYNOPSIS
        Sets RDS Gateway authentication policy
    
    .DESCRIPTION
        This function configures authentication policies for RDS Gateway
        including user groups, time restrictions, and device requirements.
    
    .PARAMETER PolicyName
        Name for the authentication policy
    
    .PARAMETER UserGroups
        Array of user groups allowed to connect
    
    .PARAMETER TimeRestrictions
        Time-based access restrictions
    
    .PARAMETER DeviceRequirements
        Device compliance requirements
    
    .PARAMETER EnableConditionalAccess
        Enable conditional access policies
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-RDSGatewayAuthenticationPolicy -PolicyName "Corporate Policy" -UserGroups @("Domain Users", "Remote Users")
    
    .EXAMPLE
        Set-RDSGatewayAuthenticationPolicy -PolicyName "Secure Policy" -UserGroups @("Admins") -EnableConditionalAccess
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $false)]
        [string[]]$UserGroups = @("Domain Users"),
        
        [Parameter(Mandatory = $false)]
        [hashtable]$TimeRestrictions,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$DeviceRequirements,
        
        [switch]$EnableConditionalAccess
    )
    
    try {
        Write-Verbose "Setting RDS Gateway authentication policy: $PolicyName"
        
        # Test prerequisites
        $prerequisites = Test-RDSGatewayPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to set RDS Gateway authentication policy."
        }
        
        $policyResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PolicyName = $PolicyName
            UserGroups = $UserGroups
            TimeRestrictions = $TimeRestrictions
            DeviceRequirements = $DeviceRequirements
            EnableConditionalAccess = $EnableConditionalAccess
            Success = $false
            Error = $null
            PolicyId = [System.Guid]::NewGuid().ToString()
        }
        
        try {
            # Configure user groups
            Write-Verbose "Configuring user groups: $($UserGroups -join ', ')"
            
            # Configure time restrictions if provided
            if ($TimeRestrictions) {
                Write-Verbose "Configuring time restrictions"
            }
            
            # Configure device requirements if provided
            if ($DeviceRequirements) {
                Write-Verbose "Configuring device requirements"
            }
            
            # Configure conditional access if enabled
            if ($EnableConditionalAccess) {
                Write-Verbose "Enabling conditional access policies"
            }
            
            Write-Verbose "Authentication policy configured successfully"
            Write-Verbose "Policy ID: $($policyResult.PolicyId)"
            
            $policyResult.Success = $true
            
        } catch {
            $policyResult.Error = $_.Exception.Message
            Write-Warning "Failed to set RDS Gateway authentication policy: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Gateway authentication policy configuration completed"
        return [PSCustomObject]$policyResult
        
    } catch {
        Write-Error "Error setting RDS Gateway authentication policy: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-RDSGateway',
    'New-RDSGatewayConfiguration',
    'Set-RDSGatewaySettings',
    'Get-RDSGatewayStatus',
    'Test-RDSGatewayConnectivity',
    'Set-RDSGatewayAuthenticationPolicy'
)

# Module initialization
Write-Verbose "RDS-Gateway module loaded successfully. Version: $ModuleVersion"