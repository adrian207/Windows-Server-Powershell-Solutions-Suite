#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Secure Windows Failover Cluster

.DESCRIPTION
    Comprehensive security hardening script for Windows Failover Clustering.
    Implements security baselines, compliance standards, and hardening measures.

.PARAMETER ClusterName
    Name of the cluster to secure

.PARAMETER SecurityLevel
    Security level to apply (Basic, Enhanced, High)

.PARAMETER ComplianceStandard
    Compliance standard to follow (CIS, NIST, SOX, HIPAA, PCI-DSS)

.PARAMETER BaselineName
    Name of the security baseline to apply

.PARAMETER IncludeNodes
    Apply security settings to cluster nodes

.PARAMETER IncludeCluster
    Apply security settings to cluster configuration

.PARAMETER EnableAuditLogging
    Enable comprehensive audit logging

.PARAMETER ConfigureCertificates
    Configure cluster certificates

.PARAMETER EnableEncryption
    Enable encryption for cluster communications

.PARAMETER ConfigureFirewall
    Configure Windows Firewall rules

.PARAMETER SecurityConfigurationFile
    Path to JSON security configuration file

.EXAMPLE
    .\Secure-Cluster.ps1 -ClusterName "PROD-CLUSTER" -SecurityLevel "High" -ComplianceStandard "CIS"

.EXAMPLE
    .\Secure-Cluster.ps1 -ClusterName "HA-CLUSTER" -SecurityLevel "Enhanced" -IncludeNodes -EnableAuditLogging -ConfigureCertificates

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive security hardening for Windows Failover Clustering.
    It implements security baselines, compliance standards, and hardening measures.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ClusterName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Enhanced", "High")]
    [string]$SecurityLevel = "Enhanced",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CIS", "NIST", "SOX", "HIPAA", "PCI-DSS")]
    [string]$ComplianceStandard = "CIS",
    
    [Parameter(Mandatory = $false)]
    [string]$BaselineName = "CIS-High",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNodes,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCluster,
    
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

Import-Module "$modulesPath\Cluster-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\Cluster-Core.psm1" -Force -ErrorAction Stop

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
    Write-SecurityLog "Starting cluster security hardening" "Info"
    Write-SecurityLog "Cluster Name: $ClusterName" "Info"
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
    }
    
    # Validate cluster exists
    Write-SecurityLog "Validating cluster existence..." "Info"
    Get-Cluster -Name $ClusterName -ErrorAction Stop | Out-Null
    Write-SecurityLog "Cluster validated successfully" "Success"
    
    # Apply security baseline
    Write-SecurityLog "Applying security baseline: $BaselineName" "Info"
    Set-ClusterSecurityBaseline -ClusterName $ClusterName -BaselineName $BaselineName -ComplianceStandard $ComplianceStandard -SecurityLevel $SecurityLevel -IncludeNodes:$IncludeNodes -IncludeCluster:$IncludeCluster
    Write-SecurityLog "Security baseline applied successfully" "Success"
    
    # Configure cluster authentication
    Write-SecurityLog "Configuring cluster authentication..." "Info"
    Set-ClusterAuthentication -ClusterName $ClusterName -AuthenticationLevel $SecurityLevel
    Write-SecurityLog "Cluster authentication configured" "Success"
    
    # Configure cluster permissions
    Write-SecurityLog "Configuring cluster permissions..." "Info"
    Set-ClusterPermissions -ClusterName $ClusterName -PermissionLevel $SecurityLevel
    Write-SecurityLog "Cluster permissions configured" "Success"
    
    # Configure cluster networks security
    Write-SecurityLog "Configuring cluster networks security..." "Info"
    Set-ClusterNetworkSecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster networks security configured" "Success"
    
    # Configure cluster resources security
    Write-SecurityLog "Configuring cluster resources security..." "Info"
    Set-ClusterResourceSecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster resources security configured" "Success"
    
    # Enable audit logging if requested
    if ($EnableAuditLogging) {
        Write-SecurityLog "Enabling comprehensive audit logging..." "Info"
        Enable-ClusterAuditLogging -ClusterName $ClusterName -AuditLevel "Comprehensive" -IncludeSecurityEvents -IncludeConfigurationChanges -IncludeResourceChanges -IncludeNetworkEvents
        Write-SecurityLog "Audit logging enabled successfully" "Success"
    }
    
    # Configure certificates if requested
    if ($ConfigureCertificates) {
        Write-SecurityLog "Configuring cluster certificates..." "Info"
        Set-ClusterCertificate -ClusterName $ClusterName -CertificateType "Cluster" -CertificateStore "LocalMachine" -CertificateSubject "CN=$ClusterName-Cluster-Cert" -SecurityLevel $SecurityLevel
        Write-SecurityLog "Cluster certificates configured" "Success"
    }
    
    # Enable encryption if requested
    if ($EnableEncryption) {
        Write-SecurityLog "Enabling cluster encryption..." "Info"
        Enable-ClusterEncryption -ClusterName $ClusterName -EncryptionLevel $SecurityLevel
        Write-SecurityLog "Cluster encryption enabled" "Success"
    }
    
    # Configure firewall if requested
    if ($ConfigureFirewall) {
        Write-SecurityLog "Configuring Windows Firewall..." "Info"
        Set-ClusterFirewallRules -ClusterName $ClusterName -SecurityLevel $SecurityLevel
        Write-SecurityLog "Windows Firewall configured" "Success"
    }
    
    # Configure cluster service accounts
    Write-SecurityLog "Configuring cluster service accounts..." "Info"
    Set-ClusterServiceAccounts -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster service accounts configured" "Success"
    
    # Configure cluster registry security
    Write-SecurityLog "Configuring cluster registry security..." "Info"
    Set-ClusterRegistrySecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster registry security configured" "Success"
    
    # Configure cluster file system security
    Write-SecurityLog "Configuring cluster file system security..." "Info"
    Set-ClusterFileSystemSecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster file system security configured" "Success"
    
    # Configure cluster event log security
    Write-SecurityLog "Configuring cluster event log security..." "Info"
    Set-ClusterEventLogSecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster event log security configured" "Success"
    
    # Configure cluster backup security
    Write-SecurityLog "Configuring cluster backup security..." "Info"
    Set-ClusterBackupSecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster backup security configured" "Success"
    
    # Configure cluster monitoring security
    Write-SecurityLog "Configuring cluster monitoring security..." "Info"
    Set-ClusterMonitoringSecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster monitoring security configured" "Success"
    
    # Configure cluster disaster recovery security
    Write-SecurityLog "Configuring cluster disaster recovery security..." "Info"
    Set-ClusterDisasterRecoverySecurity -ClusterName $ClusterName -SecurityLevel $SecurityLevel
    Write-SecurityLog "Cluster disaster recovery security configured" "Success"
    
    # Generate security report
    Write-SecurityLog "Generating security report..." "Info"
    $reportPath = Join-Path $PSScriptRoot "Cluster-Security-Report.html"
    Get-ClusterSecurityReport -ClusterName $ClusterName -ReportType "Comprehensive" -OutputPath $reportPath -Format "HTML"
    Write-SecurityLog "Security report generated: $reportPath" "Success"
    
    # Validate security configuration
    Write-SecurityLog "Validating security configuration..." "Info"
    $securityValidation = Test-ClusterSecurityConfiguration -ClusterName $ClusterName -ComplianceStandard $ComplianceStandard
    if ($securityValidation.IsCompliant) {
        Write-SecurityLog "Security configuration validation passed" "Success"
        Write-SecurityLog "Compliance Score: $($securityValidation.ComplianceScore)%" "Success"
    } else {
        Write-SecurityLog "Security configuration validation failed: $($securityValidation.Issues)" "Warning"
        Write-SecurityLog "Compliance Score: $($securityValidation.ComplianceScore)%" "Warning"
    }
    
    # Generate compliance report
    Write-SecurityLog "Generating compliance report..." "Info"
    $complianceReportPath = Join-Path $PSScriptRoot "Cluster-Compliance-Report.html"
    Get-ClusterComplianceReport -ClusterName $ClusterName -ComplianceStandard $ComplianceStandard -OutputPath $complianceReportPath -Format "HTML"
    Write-SecurityLog "Compliance report generated: $complianceReportPath" "Success"
    
    Write-SecurityLog "Cluster security hardening completed successfully" "Success"
    
    # Return security summary
    $securitySummary = @{
        ClusterName = $ClusterName
        SecurityLevel = $SecurityLevel
        ComplianceStandard = $ComplianceStandard
        BaselineName = $BaselineName
        ComplianceScore = $securityValidation.ComplianceScore
        SecurityReportPath = $reportPath
        ComplianceReportPath = $complianceReportPath
        HardeningTime = Get-Date
    }
    
    return $securitySummary
}
catch {
    Write-SecurityLog "Cluster security hardening failed: $($_.Exception.Message)" "Error"
    Write-SecurityLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive security hardening for Windows Failover Clustering.
    It implements security baselines, compliance standards, and hardening measures.
    
    Features:
    - Security baseline application
    - Compliance standard implementation
    - Cluster authentication configuration
    - Permission management
    - Network security
    - Resource security
    - Audit logging
    - Certificate management
    - Encryption configuration
    - Firewall rules
    - Service account security
    - Registry security
    - File system security
    - Event log security
    - Backup security
    - Monitoring security
    - Disaster recovery security
    - Security validation
    - Compliance reporting
    
    Prerequisites:
    - Windows Server 2016 or later
    - Failover Clustering feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - Cluster-Security.psm1
    - Cluster-Core.psm1
    
    Usage Examples:
    .\Secure-Cluster.ps1 -ClusterName "PROD-CLUSTER" -SecurityLevel "High" -ComplianceStandard "CIS"
    .\Secure-Cluster.ps1 -ClusterName "HA-CLUSTER" -SecurityLevel "Enhanced" -IncludeNodes -EnableAuditLogging -ConfigureCertificates
    .\Secure-Cluster.ps1 -ClusterName "ENTERPRISE-CLUSTER" -SecurityLevel "High" -ComplianceStandard "NIST" -BaselineName "NIST-High" -IncludeNodes -IncludeCluster -EnableAuditLogging -ConfigureCertificates -EnableEncryption -ConfigureFirewall
    
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
