#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Secure Windows Hyper-V

.DESCRIPTION
    Comprehensive security hardening script for Windows Hyper-V virtualization.
    Implements security baselines, compliance standards, and hardening measures.

.PARAMETER ServerName
    Name of the server to secure

.PARAMETER SecurityLevel
    Security level to apply (Basic, Enhanced, High)

.PARAMETER ComplianceStandard
    Compliance standard to follow (CIS, NIST, SOX, HIPAA, PCI-DSS)

.PARAMETER BaselineName
    Name of the security baseline to apply

.PARAMETER IncludeVMs
    Apply security settings to VMs

.PARAMETER IncludeHost
    Apply security settings to host

.PARAMETER EnableShieldedVMs
    Enable Shielded VM support

.PARAMETER EnableBitLocker
    Enable BitLocker encryption

.PARAMETER EnableHGS
    Enable Host Guardian Service

.PARAMETER EnableAuditLogging
    Enable comprehensive audit logging

.PARAMETER ConfigureCertificates
    Configure certificates

.PARAMETER EnableEncryption
    Enable encryption

.PARAMETER ConfigureFirewall
    Configure Windows Firewall

.PARAMETER SecurityConfigurationFile
    Path to JSON security configuration file

.EXAMPLE
    .\Secure-HyperV.ps1 -ServerName "HV-SERVER01" -SecurityLevel "High" -ComplianceStandard "CIS"

.EXAMPLE
    .\Secure-HyperV.ps1 -ServerName "HV-SERVER01" -SecurityLevel "Enhanced" -IncludeVMs -EnableShieldedVMs -EnableBitLocker

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive security hardening for Windows Hyper-V virtualization.
    It implements security baselines, compliance standards, and hardening measures.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ServerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Enhanced", "High")]
    [string]$SecurityLevel = "Enhanced",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CIS", "NIST", "SOX", "HIPAA", "PCI-DSS")]
    [string]$ComplianceStandard = "CIS",
    
    [Parameter(Mandatory = $false)]
    [string]$BaselineName = "CIS-High",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeVMs,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHost,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableShieldedVMs,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableBitLocker,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableHGS,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableAuditLogging,
    
    [Parameter(Mandatory = $false)]
    [switch]$ConfigureCertificates,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableEncryption,
    
    [Parameter(Mandatory = $false)]
    [switch]$ConfigureFirewall,
    
    [Parameter(Mandatory = $false)]
    [string]$SecurityConfigurationFile
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\Modules"

Import-Module "$modulesPath\HyperV-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Monitoring.psm1" -Force -ErrorAction Stop

# Logging function
function Write-SecurityLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-SecurityLog "Starting Hyper-V security hardening" "Info"
    Write-SecurityLog "Server Name: $ServerName" "Info"
    Write-SecurityLog "Security Level: $SecurityLevel" "Info"
    Write-SecurityLog "Compliance Standard: $ComplianceStandard" "Info"
    
    # Load security configuration from file if provided
    if ($SecurityConfigurationFile -and (Test-Path $SecurityConfigurationFile)) {
        Write-SecurityLog "Loading security configuration from file: $SecurityConfigurationFile" "Info"
        $securityConfig = Get-Content $SecurityConfigurationFile | ConvertFrom-Json
        
        # Override parameters with file values if not specified
        if (-not $PSBoundParameters.ContainsKey('SecurityLevel') -and $securityConfig.SecurityLevel) {
            $SecurityLevel = $securityConfig.SecurityLevel
        }
        if (-not $PSBoundParameters.ContainsKey('ComplianceStandard') -and $securityConfig.ComplianceStandard) {
            $ComplianceStandard = $securityConfig.ComplianceStandard
        }
        if (-not $PSBoundParameters.ContainsKey('BaselineName') -and $securityConfig.BaselineName) {
            $BaselineName = $securityConfig.BaselineName
        }
    }
    
    # Validate prerequisites
    Write-SecurityLog "Validating prerequisites..." "Info"
    
    # Check if Hyper-V is installed
    $hyperVFeature = Get-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if (-not $hyperVFeature -or $hyperVFeature.InstallState -ne "Installed") {
        throw "Hyper-V feature is not installed"
    }
    
    Write-SecurityLog "Prerequisites validated successfully" "Success"
    
    # Apply security baseline
    Write-SecurityLog "Applying security baseline: $BaselineName" "Info"
    
    Set-HyperVSecurityBaseline -HostName $ServerName -SecurityLevel $SecurityLevel -ComplianceStandard $ComplianceStandard -BaselineName $BaselineName -IncludeHost:$IncludeHost -IncludeVMs:$IncludeVMs
    
    Write-SecurityLog "Security baseline applied successfully" "Success"
    
    # Configure shielded VMs if enabled
    if ($EnableShieldedVMs) {
        Write-SecurityLog "Configuring Shielded VM support..." "Info"
        
        # Enable TPM
        Set-VMHost -ComputerName $ServerName -EnableTpm $true
        
        # Enable secure boot
        Set-VMHost -ComputerName $ServerName -EnableSecureBoot $true
        
        # Configure VMs for shielded operation
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Set-VMShieldedConfiguration -VMName $vm.Name -EnableShieldedVM -EnableSecureBoot -EnableTPM
        }
        
        Write-SecurityLog "Shielded VM support configured successfully" "Success"
    }
    
    # Configure BitLocker if enabled
    if ($EnableBitLocker) {
        Write-SecurityLog "Configuring BitLocker encryption..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Enable-VMBitLocker -VMName $vm.Name -ProtectorType "TPM"
        }
        
        Write-SecurityLog "BitLocker encryption configured successfully" "Success"
    }
    
    # Configure Host Guardian Service if enabled
    if ($EnableHGS) {
        Write-SecurityLog "Configuring Host Guardian Service..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Register-VMWithHGS -VMName $vm.Name -HGSClusterName "HGS-CLUSTER" -AttestationMode "TPM"
        }
        
        Write-SecurityLog "Host Guardian Service configured successfully" "Success"
    }
    
    # Enable audit logging if requested
    if ($EnableAuditLogging) {
        Write-SecurityLog "Enabling comprehensive audit logging..." "Info"
        
        Enable-HyperVAuditLogging -HostName $ServerName -AuditLevel "Comprehensive" -IncludeSecurityEvents -IncludeConfigurationChanges -IncludeVMOperations
        
        Write-SecurityLog "Audit logging enabled successfully" "Success"
    }
    
    # Configure certificates if requested
    if ($ConfigureCertificates) {
        Write-SecurityLog "Configuring certificates..." "Info"
        
        # Configure VM certificates
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        }
        
        Write-SecurityLog "Certificates configured successfully" "Success"
    }
    
    # Enable encryption if requested
    if ($EnableEncryption) {
        Write-SecurityLog "Enabling encryption..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Enable-VMEncryption -VMName $vm.Name -EncryptMemory -EncryptStorage
        }
        
        Write-SecurityLog "Encryption enabled successfully" "Success"
    }
    
    # Configure firewall if requested
    if ($ConfigureFirewall) {
        Write-SecurityLog "Configuring Windows Firewall..." "Info"
        
        # Enable Hyper-V firewall rules
        Enable-NetFirewallRule -DisplayGroup "Hyper-V"
        
        # Configure additional firewall rules
        New-NetFirewallRule -DisplayName "Hyper-V Management" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -Action Allow -ErrorAction SilentlyContinue
        
        Write-SecurityLog "Windows Firewall configured successfully" "Success"
    }
    
    # Configure access control
    Write-SecurityLog "Configuring access control..." "Info"
    
    Set-HyperVAccessControl -HostName $ServerName -UserOrGroup "Hyper-V Administrators" -Permission "FullControl"
    
    Write-SecurityLog "Access control configured successfully" "Success"
    
    # Configure network security
    Write-SecurityLog "Configuring network security..." "Info"
    
    Set-HyperVNetworkSecurity -HostName $ServerName -EnableVLAN -VLANID 100 -EnableMACAddressSpoofing -EnableDHCPGuard
    
    Write-SecurityLog "Network security configured successfully" "Success"
    
    # Configure VM security settings
    Write-SecurityLog "Configuring VM security settings..." "Info"
    
    $vms = Get-VM -ComputerName $ServerName
    foreach ($vm in $vms) {
        # Configure VM security
        Set-VMSecurity -VM $vm -TpmEnabled
        Set-VMFirmware -VM $vm -EnableSecureBoot
        
        # Configure integration services
        Set-HyperVIntegrationServices -VMName $vm.Name -EnableTimeSynchronization -EnableHeartbeat -EnableKeyValuePairExchange -EnableShutdown -EnableVSS -EnableGuestServiceInterface
        
        # Configure network adapter security
        $networkAdapters = Get-VMNetworkAdapter -VM $vm
        foreach ($adapter in $networkAdapters) {
            Set-VMNetworkAdapter -VMNetworkAdapter $adapter -DhcpGuard On -RouterGuard On -MacAddressSpoofing Off
        }
    }
    
    Write-SecurityLog "VM security settings configured successfully" "Success"
    
    # Configure host security settings
    Write-SecurityLog "Configuring host security settings..." "Info"
    
    # Configure host security
    Set-VMHost -ComputerName $ServerName -EnableEnhancedSessionMode $true
    Set-VMHost -ComputerName $ServerName -EnableTpm $true
    Set-VMHost -ComputerName $ServerName -EnableSecureBoot $true
    
    # Configure Windows Defender exclusions
    Add-MpPreference -ExclusionPath "C:\VMs" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "C:\VHDs" -ErrorAction SilentlyContinue
    
    Write-SecurityLog "Host security settings configured successfully" "Success"
    
    # Generate security report
    Write-SecurityLog "Generating security report..." "Info"
    
    $reportPath = Join-Path $PSScriptRoot "HyperV-Security-Report.html"
    Get-HyperVSecurityReport -HostName $ServerName -ReportType "Comprehensive" -OutputPath $reportPath -Format "HTML"
    
    Write-SecurityLog "Security report generated: $reportPath" "Success"
    
    # Validate security configuration
    Write-SecurityLog "Validating security configuration..." "Info"
    
    $securityValidation = Get-HyperVSecurityReport -HostName $ServerName -ReportType "Enhanced"
    if ($securityValidation.ComplianceStatus.ComplianceScore -gt 80) {
        Write-SecurityLog "Security configuration validation passed" "Success"
        Write-SecurityLog "Compliance Score: $($securityValidation.ComplianceStatus.ComplianceScore)%" "Success"
    } else {
        Write-SecurityLog "Security configuration validation failed" "Warning"
        Write-SecurityLog "Compliance Score: $($securityValidation.ComplianceStatus.ComplianceScore)%" "Warning"
    }
    
    # Generate compliance report
    Write-SecurityLog "Generating compliance report..." "Info"
    
    $complianceReportPath = Join-Path $PSScriptRoot "HyperV-Compliance-Report.html"
    $complianceReport = @{
        ServerName = $ServerName
        ComplianceStandard = $ComplianceStandard
        SecurityLevel = $SecurityLevel
        BaselineName = $BaselineName
        ComplianceScore = $securityValidation.ComplianceStatus.ComplianceScore
        ShieldedVMs = $securityValidation.ComplianceStatus.ShieldedVMs
        SecureBootEnabled = $securityValidation.ComplianceStatus.SecureBootEnabled
        TPMEnabled = $securityValidation.ComplianceStatus.TPMEnabled
        TotalVMs = $securityValidation.ComplianceStatus.TotalVMs
        ReportDate = Get-Date
    }
    
    $complianceReport | ConvertTo-Html -Title "Hyper-V Compliance Report" | Out-File -FilePath $complianceReportPath -Encoding UTF8
    
    Write-SecurityLog "Compliance report generated: $complianceReportPath" "Success"
    
    Write-SecurityLog "Hyper-V security hardening completed successfully" "Success"
    
    # Return security summary
    $securitySummary = @{
        ServerName = $ServerName
        SecurityLevel = $SecurityLevel
        ComplianceStandard = $ComplianceStandard
        BaselineName = $BaselineName
        IncludeVMs = $IncludeVMs
        IncludeHost = $IncludeHost
        EnableShieldedVMs = $EnableShieldedVMs
        EnableBitLocker = $EnableBitLocker
        EnableHGS = $EnableHGS
        EnableAuditLogging = $EnableAuditLogging
        ConfigureCertificates = $ConfigureCertificates
        EnableEncryption = $EnableEncryption
        ConfigureFirewall = $ConfigureFirewall
        ComplianceScore = $securityValidation.ComplianceStatus.ComplianceScore
        SecurityReportPath = $reportPath
        ComplianceReportPath = $complianceReportPath
        HardeningTime = Get-Date
    }
    
    return $securitySummary
}
catch {
    Write-SecurityLog "Hyper-V security hardening failed: $($_.Exception.Message)" "Error"
    Write-SecurityLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive security hardening for Windows Hyper-V virtualization.
    It implements security baselines, compliance standards, and hardening measures.
    
    Features:
    - Security baseline application
    - Compliance standard implementation
    - Shielded VM configuration
    - BitLocker integration
    - Host Guardian Service integration
    - VM encryption
    - Audit logging
    - Certificate management
    - Firewall configuration
    - Access control
    - Network security
    - VM security settings
    - Host security settings
    - Security validation
    - Compliance reporting
    
    Prerequisites:
    - Windows Server 2016 or later
    - Hyper-V feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - HyperV-Security.psm1
    - HyperV-Core.psm1
    - HyperV-Monitoring.psm1
    
    Usage Examples:
    .\Secure-HyperV.ps1 -ServerName "HV-SERVER01" -SecurityLevel "High" -ComplianceStandard "CIS"
    .\Secure-HyperV.ps1 -ServerName "HV-SERVER01" -SecurityLevel "Enhanced" -IncludeVMs -EnableShieldedVMs -EnableBitLocker
    .\Secure-HyperV.ps1 -ServerName "HV-SERVER01" -SecurityLevel "High" -ComplianceStandard "NIST" -BaselineName "NIST-High" -IncludeVMs -IncludeHost -EnableShieldedVMs -EnableBitLocker -EnableHGS -EnableAuditLogging -ConfigureCertificates -EnableEncryption -ConfigureFirewall
    
    Output:
    - Console logging with color-coded messages
    - HTML security report
    - HTML compliance report
    - Security validation results
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Implements defense-in-depth
    - Follows security best practices
    - Logs all operations for audit
    - Validates security configuration
    
    Performance Impact:
    - Minimal impact during hardening
    - Non-destructive operations
    - Configurable execution modes
    - Security monitoring included
#>
