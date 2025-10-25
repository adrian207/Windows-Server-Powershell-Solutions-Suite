#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Privileged Access Workstations (PAW) RDS Environment

.DESCRIPTION
    This script deploys a secure RDS environment specifically designed for Privileged Access Workstations,
    including enhanced security, auditing, and compliance features.

.PARAMETER DeploymentName
    Name for the PAW RDS deployment

.PARAMETER SecurityLevel
    Security level (High, Critical, Maximum)

.PARAMETER EnableAppLocker
    Enable AppLocker for application control

.PARAMETER EnableDeviceGuard
    Enable Device Guard for code integrity

.PARAMETER EnableCredentialGuard
    Enable Credential Guard for credential protection

.PARAMETER EnableAuditLogging
    Enable comprehensive audit logging

.PARAMETER AdminGroups
    Array of admin groups to grant access

.PARAMETER EnableMFA
    Enable multi-factor authentication

.PARAMETER LogFile
    Log file path for deployment

.EXAMPLE
    .\Deploy-PrivilegedAccessWorkstations.ps1 -DeploymentName "PAW-RDS" -SecurityLevel "Critical" -AdminGroups @("Domain Admins", "Enterprise Admins")

.EXAMPLE
    .\Deploy-PrivilegedAccessWorkstations.ps1 -DeploymentName "PAW-RDS" -SecurityLevel "Maximum" -EnableAppLocker -EnableDeviceGuard -EnableCredentialGuard -EnableAuditLogging -EnableMFA
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("High", "Critical", "Maximum")]
    [string]$SecurityLevel = "Critical",
    
    [switch]$EnableAppLocker,
    
    [switch]$EnableDeviceGuard,
    
    [switch]$EnableCredentialGuard,
    
    [switch]$EnableAuditLogging,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AdminGroups = @("Domain Admins"),
    
    [switch]$EnableMFA,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = "C:\Logs\PAW-RDS-Deployment.log"
)

# Set up logging
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-DeploymentLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

try {
    Write-DeploymentLog "Starting Privileged Access Workstations RDS Deployment: $DeploymentName"
    
    # Import RDS modules
    $modulePaths = @(
        ".\Modules\RDS-Core.psm1",
        ".\Modules\RDS-SessionHost.psm1",
        ".\Modules\RDS-Gateway.psm1",
        ".\Modules\RDS-Security.psm1",
        ".\Modules\RDS-Monitoring.psm1"
    )
    
    foreach ($modulePath in $modulePaths) {
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force
            Write-DeploymentLog "Imported module: $modulePath"
        } else {
            Write-DeploymentLog "Module not found: $modulePath" "WARNING"
        }
    }
    
    # Test prerequisites
    Write-DeploymentLog "Testing prerequisites..."
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites.AdministratorPrivileges) {
        throw "Administrator privileges are required for PAW RDS deployment"
    }
    
    # Step 1: Install RDS Session Host
    Write-DeploymentLog "Installing RDS Session Host..."
    $sessionHostResult = Install-RDSSessionHost -IncludeManagementTools -RestartRequired
    if ($sessionHostResult.Success) {
        Write-DeploymentLog "RDS Session Host installed successfully"
    } else {
        throw "Failed to install RDS Session Host: $($sessionHostResult.Error)"
    }
    
    # Step 2: Install RD Gateway for secure access
    Write-DeploymentLog "Installing RD Gateway for secure access..."
    $gatewayResult = Install-RDSGateway -IncludeManagementTools -RestartRequired
    if ($gatewayResult.Success) {
        Write-DeploymentLog "RD Gateway installed successfully"
    } else {
        throw "Failed to install RD Gateway: $($gatewayResult.Error)"
    }
    
    # Step 3: Configure security policy based on security level
    Write-DeploymentLog "Configuring security policy for level: $SecurityLevel..."
    $securityConfig = @{
        EnableAppLocker = $EnableAppLocker
        EnableDeviceGuard = $EnableDeviceGuard
        EnableCredentialGuard = $EnableCredentialGuard
        EnableAuditLogging = $EnableAuditLogging
        SecurityLevel = $SecurityLevel
    }
    
    $securityResult = Set-RDSSecurityPolicy @securityConfig
    if ($securityResult.Success) {
        Write-DeploymentLog "Security policy configured successfully"
    } else {
        throw "Failed to configure security policy: $($securityResult.Error)"
    }
    
    # Step 4: Configure RD Gateway security
    Write-DeploymentLog "Configuring RD Gateway security..."
    $gatewaySecurityResult = Set-RDSGatewaySettings -EnableSSL -RequireClientCertificates -EnableMFA:$EnableMFA -EnableAuditLogging:$EnableAuditLogging
    if ($gatewaySecurityResult.Success) {
        Write-DeploymentLog "RD Gateway security configured successfully"
    } else {
        Write-DeploymentLog "Failed to configure RD Gateway security: $($gatewaySecurityResult.Error)" "WARNING"
    }
    
    # Step 5: Configure admin group access
    Write-DeploymentLog "Configuring admin group access..."
    foreach ($group in $AdminGroups) {
        try {
            $accessResult = Set-RDSUserAccess -UserGroup $group -AccessLevel "Administrative" -EnablePrivilegedAccess
            if ($accessResult.Success) {
                Write-DeploymentLog "Configured privileged access for group: $group"
            } else {
                Write-DeploymentLog "Failed to configure privileged access for group $group : $($accessResult.Error)" "WARNING"
            }
        } catch {
            Write-DeploymentLog "Error configuring privileged access for group $group : $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Step 6: Configure PAW-specific registry settings
    Write-DeploymentLog "Configuring PAW-specific settings..."
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\PAW"
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $registryPath -Name "DeploymentName" -Value $DeploymentName -Type String
        Set-ItemProperty -Path $registryPath -Name "SecurityLevel" -Value $SecurityLevel -Type String
        Set-ItemProperty -Path $registryPath -Name "EnableAppLocker" -Value ([int]$EnableAppLocker) -Type DWord
        Set-ItemProperty -Path $registryPath -Name "EnableDeviceGuard" -Value ([int]$EnableDeviceGuard) -Type DWord
        Set-ItemProperty -Path $registryPath -Name "EnableCredentialGuard" -Value ([int]$EnableCredentialGuard) -Type DWord
        Set-ItemProperty -Path $registryPath -Name "EnableAuditLogging" -Value ([int]$EnableAuditLogging) -Type DWord
        Set-ItemProperty -Path $registryPath -Name "EnableMFA" -Value ([int]$EnableMFA) -Type DWord
        
        # PAW-specific security settings
        Set-ItemProperty -Path $registryPath -Name "RestrictLocalAdmin" -Value 1 -Type DWord
        Set-ItemProperty -Path $registryPath -Name "EnablePrivilegedAccess" -Value 1 -Type DWord
        Set-ItemProperty -Path $registryPath -Name "AuditLevel" -Value "Maximum" -Type String
        
        Write-DeploymentLog "PAW-specific registry settings configured"
    } catch {
        Write-DeploymentLog "Failed to configure PAW-specific registry settings: $($_.Exception.Message)" "WARNING"
    }
    
    # Step 7: Configure Windows Security Center settings
    Write-DeploymentLog "Configuring Windows Security Center settings..."
    try {
        # Enable Windows Defender Advanced Threat Protection
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableOnAccessProtection $false
        
        # Configure Windows Firewall for PAW
        New-NetFirewallRule -DisplayName "PAW RDS Access" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Domain
        
        Write-DeploymentLog "Windows Security Center settings configured"
    } catch {
        Write-DeploymentLog "Failed to configure Windows Security Center settings: $($_.Exception.Message)" "WARNING"
    }
    
    # Step 8: Configure audit logging
    if ($EnableAuditLogging) {
        Write-DeploymentLog "Configuring comprehensive audit logging..."
        try {
            # Enable audit policies
            auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
            auditpol /set /category:"Object Access" /success:enable /failure:enable
            auditpol /set /category:"Privilege Use" /success:enable /failure:enable
            auditpol /set /category:"System" /success:enable /failure:enable
            
            # Configure event log settings
            wevtutil sl Security /ms:67108864
            wevtutil sl System /ms:67108864
            wevtutil sl Application /ms:67108864
            
            Write-DeploymentLog "Audit logging configured successfully"
        } catch {
            Write-DeploymentLog "Failed to configure audit logging: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Step 9: Start PAW monitoring
    Write-DeploymentLog "Starting PAW monitoring..."
    $monitoringResult = Start-RDSMonitoring -MonitoringType "Security" -LogFile "C:\Logs\PAW-Security-Monitor.log" -ContinuousMonitoring
    if ($monitoringResult.Success) {
        Write-DeploymentLog "PAW monitoring started successfully"
    } else {
        Write-DeploymentLog "Failed to start PAW monitoring: $($monitoringResult.Error)" "WARNING"
    }
    
    # Step 10: Verify PAW deployment
    Write-DeploymentLog "Verifying PAW deployment..."
    $verificationResult = Test-RDSSecurityCompliance -SecurityLevel $SecurityLevel
    if ($verificationResult.Success) {
        Write-DeploymentLog "PAW deployment verification successful"
        Write-DeploymentLog "Security Compliance Score: $($verificationResult.ComplianceScore)%"
    } else {
        Write-DeploymentLog "PAW deployment verification failed: $($verificationResult.Error)" "WARNING"
    }
    
    # Step 11: Verify deployment
    Write-DeploymentLog "Deployment Summary:" "INFO"
    Write-DeploymentLog "  - Deployment Name: $DeploymentName" "INFO"
    Write-DeploymentLog "  - Security Level: $SecurityLevel" "INFO"
    Write-DeploymentLog "  - AppLocker: $EnableAppLocker" "INFO"
    Write-DeploymentLog "  - Device Guard: $EnableDeviceGuard" "INFO"
    Write-DeploymentLog "  - Credential Guard: $EnableCredentialGuard" "INFO"
    Write-DeploymentLog "  - Audit Logging: $EnableAuditLogging" "INFO"
    Write-DeploymentLog "  - Multi-Factor Auth: $EnableMFA" "INFO"
    Write-DeploymentLog "  - Admin Groups: $($AdminGroups -join ', ')" "INFO"
    
    Write-DeploymentLog "Privileged Access Workstations RDS Deployment completed successfully!" "SUCCESS"
    
} catch {
    Write-DeploymentLog "Deployment failed: $($_.Exception.Message)" "ERROR"
    Write-Error "Privileged Access Workstations RDS Deployment failed: $($_.Exception.Message)"
    exit 1
}
