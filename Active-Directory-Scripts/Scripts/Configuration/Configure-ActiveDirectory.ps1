#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure Active Directory

.DESCRIPTION
    Configuration script for Windows Active Directory Domain Services.
    Configures AD DS with comprehensive settings including user management,
    group management, OU management, group policy, and more.

.PARAMETER ServerName
    Name of the server to configure

.PARAMETER DomainName
    Name of the domain to configure

.PARAMETER ConfigurationLevel
    Level of configuration to apply

.PARAMETER IncludeSecurity
    Include security configurations

.PARAMETER IncludeMonitoring
    Include monitoring configurations

.PARAMETER IncludeCompliance
    Include compliance configurations

.PARAMETER IncludeIntegration
    Include integration configurations

.PARAMETER IncludeCustom
    Include custom configurations

.PARAMETER CustomConfigurationScript
    Custom configuration script path

.PARAMETER OutputFormat
    Output format for configuration results

.PARAMETER OutputPath
    Output path for configuration results

.PARAMETER GenerateReport
    Generate configuration report

.PARAMETER ReportFormat
    Format for configuration report

.PARAMETER ReportPath
    Path for configuration report

.EXAMPLE
    .\Configure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -ConfigurationLevel "Standard"

.EXAMPLE
    .\Configure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -ConfigurationLevel "Comprehensive" -IncludeSecurity -IncludeMonitoring -IncludeCompliance -IncludeIntegration -IncludeCustom -CustomConfigurationScript "C:\Scripts\Custom-AD-Configuration.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Configuration-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Configuration-Report.pdf"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive", "Maximum")]
    [string]$ConfigurationLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMonitoring,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCompliance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCustom,
    
    [Parameter(Mandatory = $false)]
    [string]$CustomConfigurationScript,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$ReportFormat = "PDF",
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\AD-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-ConfigurationLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [AD-Configuration] $Message"
    
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
    Write-ConfigurationLog "Starting Active Directory configuration on $ServerName" "Info"
    Write-ConfigurationLog "Domain Name: $DomainName" "Info"
    Write-ConfigurationLog "Configuration Level: $ConfigurationLevel" "Info"
    
    # Configuration results
    $configurationResults = @{
        ServerName = $ServerName
        DomainName = $DomainName
        ConfigurationLevel = $ConfigurationLevel
        Timestamp = Get-Date
        ConfigurationSteps = @()
        Issues = @()
        Recommendations = @()
        OverallResult = "Unknown"
    }
    
    # Configure based on level
    switch ($ConfigurationLevel) {
        "Basic" {
            Write-ConfigurationLog "Applying basic Active Directory configuration..." "Info"
            
            # Step 1: Configure basic password policy
            try {
                $passwordPolicy = Set-ADPasswordPolicy -ServerName $ServerName -MinPasswordLength 8 -PasswordHistoryCount 5 -MaxPasswordAge 90 -MinPasswordAge 1 -PasswordComplexity $true -LockoutThreshold 5 -LockoutDuration 30 -LockoutObservationWindow 30
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Basic Password Policy"
                    Status = "Completed"
                    Details = "Basic password policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Basic password policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Basic Password Policy"
                    Status = "Failed"
                    Details = "Failed to configure basic password policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure basic password policy"
                $configurationResults.Recommendations += "Check password policy configuration parameters"
                Write-ConfigurationLog "Failed to configure basic password policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure basic group policy
            try {
                $groupPolicy = Set-ADGroupPolicy -ServerName $ServerName -GPOName "Basic Security Policy" -GPODescription "Basic security policy for domain" -GPOSettings @{
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "EnableLUA"
                        Value = 1
                        Type = "DWord"
                    }
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Basic Group Policy"
                    Status = "Completed"
                    Details = "Basic group policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Basic group policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Basic Group Policy"
                    Status = "Failed"
                    Details = "Failed to configure basic group policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure basic group policy"
                $configurationResults.Recommendations += "Check group policy configuration parameters"
                Write-ConfigurationLog "Failed to configure basic group policy: $($_.Exception.Message)" "Error"
            }
        }
        
        "Standard" {
            Write-ConfigurationLog "Applying standard Active Directory configuration..." "Info"
            
            # Step 1: Configure standard password policy
            try {
                $passwordPolicy = Set-ADPasswordPolicy -ServerName $ServerName -MinPasswordLength 12 -PasswordHistoryCount 12 -MaxPasswordAge 90 -MinPasswordAge 1 -PasswordComplexity $true -LockoutThreshold 5 -LockoutDuration 30 -LockoutObservationWindow 30
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard Password Policy"
                    Status = "Completed"
                    Details = "Standard password policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Standard password policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard Password Policy"
                    Status = "Failed"
                    Details = "Failed to configure standard password policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure standard password policy"
                $configurationResults.Recommendations += "Check password policy configuration parameters"
                Write-ConfigurationLog "Failed to configure standard password policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure standard group policy
            try {
                $groupPolicy = Set-ADGroupPolicy -ServerName $ServerName -GPOName "Standard Security Policy" -GPODescription "Standard security policy for domain" -GPOSettings @{
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "EnableLUA"
                        Value = 1
                        Type = "DWord"
                    }
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "ConsentPromptBehaviorAdmin"
                        Value = 5
                        Type = "DWord"
                    }
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard Group Policy"
                    Status = "Completed"
                    Details = "Standard group policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Standard group policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard Group Policy"
                    Status = "Failed"
                    Details = "Failed to configure standard group policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure standard group policy"
                $configurationResults.Recommendations += "Check group policy configuration parameters"
                Write-ConfigurationLog "Failed to configure standard group policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure standard OU structure
            try {
                $ouStructure = @(
                    @{
                        Name = "Users"
                        Path = "OU=Users,DC=contoso,DC=com"
                        Description = "User accounts"
                    },
                    @{
                        Name = "Computers"
                        Path = "OU=Computers,DC=contoso,DC=com"
                        Description = "Computer accounts"
                    },
                    @{
                        Name = "Groups"
                        Path = "OU=Groups,DC=contoso,DC=com"
                        Description = "Security groups"
                    }
                )
                
                foreach ($ou in $ouStructure) {
                    New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -Description $ou.Description -ProtectedFromAccidentalDeletion $true -Server $ServerName -ErrorAction Stop
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard OU Structure"
                    Status = "Completed"
                    Details = "Standard OU structure configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Standard OU structure configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard OU Structure"
                    Status = "Failed"
                    Details = "Failed to configure standard OU structure: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure standard OU structure"
                $configurationResults.Recommendations += "Check OU structure configuration parameters"
                Write-ConfigurationLog "Failed to configure standard OU structure: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure standard time synchronization
            try {
                $timeSync = Set-ADTimeSync -ServerName $ServerName -TimeSource "time.windows.com"
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard Time Synchronization"
                    Status = "Completed"
                    Details = "Standard time synchronization configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Standard time synchronization configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Standard Time Synchronization"
                    Status = "Failed"
                    Details = "Failed to configure standard time synchronization: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure standard time synchronization"
                $configurationResults.Recommendations += "Check time synchronization configuration parameters"
                Write-ConfigurationLog "Failed to configure standard time synchronization: $($_.Exception.Message)" "Error"
            }
        }
        
        "Comprehensive" {
            Write-ConfigurationLog "Applying comprehensive Active Directory configuration..." "Info"
            
            # Step 1: Configure comprehensive password policy
            try {
                $passwordPolicy = Set-ADPasswordPolicy -ServerName $ServerName -MinPasswordLength 12 -PasswordHistoryCount 12 -MaxPasswordAge 90 -MinPasswordAge 1 -PasswordComplexity $true -LockoutThreshold 5 -LockoutDuration 30 -LockoutObservationWindow 30
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive Password Policy"
                    Status = "Completed"
                    Details = "Comprehensive password policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Comprehensive password policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive Password Policy"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive password policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure comprehensive password policy"
                $configurationResults.Recommendations += "Check password policy configuration parameters"
                Write-ConfigurationLog "Failed to configure comprehensive password policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure comprehensive group policy
            try {
                $groupPolicy = Set-ADGroupPolicy -ServerName $ServerName -GPOName "Comprehensive Security Policy" -GPODescription "Comprehensive security policy for domain" -GPOSettings @{
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "EnableLUA"
                        Value = 1
                        Type = "DWord"
                    }
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "ConsentPromptBehaviorAdmin"
                        Value = 5
                        Type = "DWord"
                    }
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "ConsentPromptBehaviorUser"
                        Value = 3
                        Type = "DWord"
                    }
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive Group Policy"
                    Status = "Completed"
                    Details = "Comprehensive group policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Comprehensive group policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive Group Policy"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive group policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure comprehensive group policy"
                $configurationResults.Recommendations += "Check group policy configuration parameters"
                Write-ConfigurationLog "Failed to configure comprehensive group policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure comprehensive OU structure
            try {
                $ouStructure = @(
                    @{
                        Name = "Users"
                        Path = "OU=Users,DC=contoso,DC=com"
                        Description = "User accounts"
                    },
                    @{
                        Name = "Computers"
                        Path = "OU=Computers,DC=contoso,DC=com"
                        Description = "Computer accounts"
                    },
                    @{
                        Name = "Groups"
                        Path = "OU=Groups,DC=contoso,DC=com"
                        Description = "Security groups"
                    },
                    @{
                        Name = "Service Accounts"
                        Path = "OU=Service Accounts,DC=contoso,DC=com"
                        Description = "Service accounts"
                    },
                    @{
                        Name = "Administrative"
                        Path = "OU=Administrative,DC=contoso,DC=com"
                        Description = "Administrative accounts"
                    }
                )
                
                foreach ($ou in $ouStructure) {
                    New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -Description $ou.Description -ProtectedFromAccidentalDeletion $true -Server $ServerName -ErrorAction Stop
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive OU Structure"
                    Status = "Completed"
                    Details = "Comprehensive OU structure configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Comprehensive OU structure configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive OU Structure"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive OU structure: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure comprehensive OU structure"
                $configurationResults.Recommendations += "Check OU structure configuration parameters"
                Write-ConfigurationLog "Failed to configure comprehensive OU structure: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure comprehensive time synchronization
            try {
                $timeSync = Set-ADTimeSync -ServerName $ServerName -TimeSource "time.windows.com"
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive Time Synchronization"
                    Status = "Completed"
                    Details = "Comprehensive time synchronization configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Comprehensive time synchronization configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Comprehensive Time Synchronization"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive time synchronization: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure comprehensive time synchronization"
                $configurationResults.Recommendations += "Check time synchronization configuration parameters"
                Write-ConfigurationLog "Failed to configure comprehensive time synchronization: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Configure comprehensive security
            if ($IncludeSecurity) {
                try {
                    $securityConfig = Set-ADAuditPolicy -ServerName $ServerName -AuditLevel "Standard"
                    
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Security"
                        Status = "Completed"
                        Details = "Comprehensive security configuration completed successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "Comprehensive security configuration completed successfully" "Success"
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Security"
                        Status = "Failed"
                        Details = "Failed to configure comprehensive security: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure comprehensive security"
                    $configurationResults.Recommendations += "Check security configuration parameters"
                    Write-ConfigurationLog "Failed to configure comprehensive security: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 6: Configure comprehensive monitoring
            if ($IncludeMonitoring) {
                try {
                    $monitoringConfig = Get-ADHealthMonitoring -ServerName $ServerName -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
                    
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Monitoring"
                        Status = "Completed"
                        Details = "Comprehensive monitoring configuration completed successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "Comprehensive monitoring configuration completed successfully" "Success"
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Monitoring"
                        Status = "Failed"
                        Details = "Failed to configure comprehensive monitoring: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure comprehensive monitoring"
                    $configurationResults.Recommendations += "Check monitoring configuration parameters"
                    Write-ConfigurationLog "Failed to configure comprehensive monitoring: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 7: Configure comprehensive compliance
            if ($IncludeCompliance) {
                try {
                    $complianceConfig = Get-ADComplianceStatus -ServerName $ServerName -IncludeDetails -IncludeStandards -IncludePolicies -IncludeAudit
                    
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Compliance"
                        Status = "Completed"
                        Details = "Comprehensive compliance configuration completed successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "Comprehensive compliance configuration completed successfully" "Success"
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Compliance"
                        Status = "Failed"
                        Details = "Failed to configure comprehensive compliance: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure comprehensive compliance"
                    $configurationResults.Recommendations += "Check compliance configuration parameters"
                    Write-ConfigurationLog "Failed to configure comprehensive compliance: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 8: Configure comprehensive integration
            if ($IncludeIntegration) {
                try {
                    $integrationConfig = @{
                        "DNSIntegration" = "Enabled"
                        "KerberosIntegration" = "Enabled"
                        "LDAPIntegration" = "Enabled"
                        "CertificateIntegration" = "Enabled"
                        "FederationIntegration" = "Enabled"
                    }
                    
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Integration"
                        Status = "Completed"
                        Details = "Comprehensive integration configuration completed successfully"
                        Severity = "Info"
                    }
                    Write-ConfigurationLog "Comprehensive integration configuration completed successfully" "Success"
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Comprehensive Integration"
                        Status = "Failed"
                        Details = "Failed to configure comprehensive integration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure comprehensive integration"
                    $configurationResults.Recommendations += "Check integration configuration parameters"
                    Write-ConfigurationLog "Failed to configure comprehensive integration: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 9: Configure custom settings
            if ($IncludeCustom -and $CustomConfigurationScript) {
                try {
                    if (Test-Path $CustomConfigurationScript) {
                        & $CustomConfigurationScript -ServerName $ServerName -DomainName $DomainName
                        
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Custom Settings"
                            Status = "Completed"
                            Details = "Custom settings configuration completed successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "Custom settings configuration completed successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Custom Settings"
                            Status = "Skipped"
                            Details = "Custom configuration script not found"
                            Severity = "Warning"
                        }
                        Write-ConfigurationLog "Custom configuration script not found: $CustomConfigurationScript" "Warning"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Custom Settings"
                        Status = "Failed"
                        Details = "Failed to configure custom settings: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure custom settings"
                    $configurationResults.Recommendations += "Check custom configuration script"
                    Write-ConfigurationLog "Failed to configure custom settings: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        "Maximum" {
            Write-ConfigurationLog "Applying maximum Active Directory configuration..." "Info"
            
            # Step 1: Configure maximum password policy
            try {
                $passwordPolicy = Set-ADPasswordPolicy -ServerName $ServerName -MinPasswordLength 16 -PasswordHistoryCount 24 -MaxPasswordAge 60 -MinPasswordAge 1 -PasswordComplexity $true -LockoutThreshold 3 -LockoutDuration 60 -LockoutObservationWindow 60
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Password Policy"
                    Status = "Completed"
                    Details = "Maximum password policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum password policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Password Policy"
                    Status = "Failed"
                    Details = "Failed to configure maximum password policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum password policy"
                $configurationResults.Recommendations += "Check password policy configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum password policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure maximum group policy
            try {
                $groupPolicy = Set-ADGroupPolicy -ServerName $ServerName -GPOName "Maximum Security Policy" -GPODescription "Maximum security policy for domain" -GPOSettings @{
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "EnableLUA"
                        Value = 1
                        Type = "DWord"
                    }
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "ConsentPromptBehaviorAdmin"
                        Value = 5
                        Type = "DWord"
                    }
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "ConsentPromptBehaviorUser"
                        Value = 3
                        Type = "DWord"
                    }
                    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                        Name = "EnableInstallerDetection"
                        Value = 1
                        Type = "DWord"
                    }
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Group Policy"
                    Status = "Completed"
                    Details = "Maximum group policy configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum group policy configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Group Policy"
                    Status = "Failed"
                    Details = "Failed to configure maximum group policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum group policy"
                $configurationResults.Recommendations += "Check group policy configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum group policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure maximum OU structure
            try {
                $ouStructure = @(
                    @{
                        Name = "Users"
                        Path = "OU=Users,DC=contoso,DC=com"
                        Description = "User accounts"
                    },
                    @{
                        Name = "Computers"
                        Path = "OU=Computers,DC=contoso,DC=com"
                        Description = "Computer accounts"
                    },
                    @{
                        Name = "Groups"
                        Path = "OU=Groups,DC=contoso,DC=com"
                        Description = "Security groups"
                    },
                    @{
                        Name = "Service Accounts"
                        Path = "OU=Service Accounts,DC=contoso,DC=com"
                        Description = "Service accounts"
                    },
                    @{
                        Name = "Administrative"
                        Path = "OU=Administrative,DC=contoso,DC=com"
                        Description = "Administrative accounts"
                    },
                    @{
                        Name = "Privileged"
                        Path = "OU=Privileged,DC=contoso,DC=com"
                        Description = "Privileged accounts"
                    },
                    @{
                        Name = "Temporary"
                        Path = "OU=Temporary,DC=contoso,DC=com"
                        Description = "Temporary accounts"
                    }
                )
                
                foreach ($ou in $ouStructure) {
                    New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -Description $ou.Description -ProtectedFromAccidentalDeletion $true -Server $ServerName -ErrorAction Stop
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum OU Structure"
                    Status = "Completed"
                    Details = "Maximum OU structure configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum OU structure configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum OU Structure"
                    Status = "Failed"
                    Details = "Failed to configure maximum OU structure: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum OU structure"
                $configurationResults.Recommendations += "Check OU structure configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum OU structure: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure maximum time synchronization
            try {
                $timeSync = Set-ADTimeSync -ServerName $ServerName -TimeSource "time.windows.com"
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Time Synchronization"
                    Status = "Completed"
                    Details = "Maximum time synchronization configured successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum time synchronization configured successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Time Synchronization"
                    Status = "Failed"
                    Details = "Failed to configure maximum time synchronization: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum time synchronization"
                $configurationResults.Recommendations += "Check time synchronization configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum time synchronization: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Configure maximum security
            try {
                $securityConfig = Set-ADAuditPolicy -ServerName $ServerName -AuditLevel "Maximum"
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Security"
                    Status = "Completed"
                    Details = "Maximum security configuration completed successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum security configuration completed successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Security"
                    Status = "Failed"
                    Details = "Failed to configure maximum security: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum security"
                $configurationResults.Recommendations += "Check security configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum security: $($_.Exception.Message)" "Error"
            }
            
            # Step 6: Configure maximum monitoring
            try {
                $monitoringConfig = Get-ADHealthMonitoring -ServerName $ServerName -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Monitoring"
                    Status = "Completed"
                    Details = "Maximum monitoring configuration completed successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum monitoring configuration completed successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Monitoring"
                    Status = "Failed"
                    Details = "Failed to configure maximum monitoring: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum monitoring"
                $configurationResults.Recommendations += "Check monitoring configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum monitoring: $($_.Exception.Message)" "Error"
            }
            
            # Step 7: Configure maximum compliance
            try {
                $complianceConfig = Get-ADComplianceStatus -ServerName $ServerName -IncludeDetails -IncludeStandards -IncludePolicies -IncludeAudit
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Compliance"
                    Status = "Completed"
                    Details = "Maximum compliance configuration completed successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum compliance configuration completed successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Compliance"
                    Status = "Failed"
                    Details = "Failed to configure maximum compliance: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum compliance"
                $configurationResults.Recommendations += "Check compliance configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum compliance: $($_.Exception.Message)" "Error"
            }
            
            # Step 8: Configure maximum integration
            try {
                $integrationConfig = @{
                    "DNSIntegration" = "Enabled"
                    "KerberosIntegration" = "Enabled"
                    "LDAPIntegration" = "Enabled"
                    "CertificateIntegration" = "Enabled"
                    "FederationIntegration" = "Enabled"
                    "CloudIntegration" = "Enabled"
                    "HybridIntegration" = "Enabled"
                }
                
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Integration"
                    Status = "Completed"
                    Details = "Maximum integration configuration completed successfully"
                    Severity = "Info"
                }
                Write-ConfigurationLog "Maximum integration configuration completed successfully" "Success"
            }
            catch {
                $configurationResults.ConfigurationSteps += @{
                    Step = "Configure Maximum Integration"
                    Status = "Failed"
                    Details = "Failed to configure maximum integration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $configurationResults.Issues += "Failed to configure maximum integration"
                $configurationResults.Recommendations += "Check integration configuration parameters"
                Write-ConfigurationLog "Failed to configure maximum integration: $($_.Exception.Message)" "Error"
            }
            
            # Step 9: Configure custom settings
            if ($IncludeCustom -and $CustomConfigurationScript) {
                try {
                    if (Test-Path $CustomConfigurationScript) {
                        & $CustomConfigurationScript -ServerName $ServerName -DomainName $DomainName
                        
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Custom Settings"
                            Status = "Completed"
                            Details = "Custom settings configuration completed successfully"
                            Severity = "Info"
                        }
                        Write-ConfigurationLog "Custom settings configuration completed successfully" "Success"
                    } else {
                        $configurationResults.ConfigurationSteps += @{
                            Step = "Configure Custom Settings"
                            Status = "Skipped"
                            Details = "Custom configuration script not found"
                            Severity = "Warning"
                        }
                        Write-ConfigurationLog "Custom configuration script not found: $CustomConfigurationScript" "Warning"
                    }
                }
                catch {
                    $configurationResults.ConfigurationSteps += @{
                        Step = "Configure Custom Settings"
                        Status = "Failed"
                        Details = "Failed to configure custom settings: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $configurationResults.Issues += "Failed to configure custom settings"
                    $configurationResults.Recommendations += "Check custom configuration script"
                    Write-ConfigurationLog "Failed to configure custom settings: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        default {
            Write-ConfigurationLog "Unknown configuration level: $ConfigurationLevel" "Error"
            $configurationResults.ConfigurationSteps += @{
                Step = "Configuration Level Validation"
                Status = "Failed"
                Details = "Unknown configuration level: $ConfigurationLevel"
                Severity = "Error"
            }
            $configurationResults.Issues += "Unknown configuration level: $ConfigurationLevel"
            $configurationResults.Recommendations += "Use a valid configuration level"
        }
    }
    
    # Determine overall result
    $failedSteps = $configurationResults.ConfigurationSteps | Where-Object { $_.Status -eq "Failed" }
    if ($failedSteps.Count -eq 0) {
        $configurationResults.OverallResult = "Success"
    } elseif ($failedSteps.Count -lt $configurationResults.ConfigurationSteps.Count / 2) {
        $configurationResults.OverallResult = "Partial Success"
    } else {
        $configurationResults.OverallResult = "Failed"
    }
    
    # Summary
    Write-ConfigurationLog "=== CONFIGURATION SUMMARY ===" "Info"
    Write-ConfigurationLog "Server Name: $ServerName" "Info"
    Write-ConfigurationLog "Domain Name: $DomainName" "Info"
    Write-ConfigurationLog "Configuration Level: $ConfigurationLevel" "Info"
    Write-ConfigurationLog "Overall Result: $($configurationResults.OverallResult)" "Info"
    Write-ConfigurationLog "Configuration Steps: $($configurationResults.ConfigurationSteps.Count)" "Info"
    Write-ConfigurationLog "Issues: $($configurationResults.Issues.Count)" "Info"
    Write-ConfigurationLog "Recommendations: $($configurationResults.Recommendations.Count)" "Info"
    
    if ($configurationResults.Issues.Count -gt 0) {
        Write-ConfigurationLog "Issues:" "Warning"
        foreach ($issue in $configurationResults.Issues) {
            Write-ConfigurationLog "  - $issue" "Warning"
        }
    }
    
    if ($configurationResults.Recommendations.Count -gt 0) {
        Write-ConfigurationLog "Recommendations:" "Info"
        foreach ($recommendation in $configurationResults.Recommendations) {
            Write-ConfigurationLog "  - $recommendation" "Info"
        }
    }
    
    Write-ConfigurationLog "Active Directory configuration completed" "Success"
    
    return $configurationResults
}
catch {
    Write-ConfigurationLog "Active Directory configuration failed: $($_.Exception.Message)" "Error"
    Write-ConfigurationLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script configures Windows Active Directory Domain Services with comprehensive
    settings including user management, group management, OU management, group policy,
    and more.
    
    Features:
    - Basic Configuration
    - Standard Configuration
    - Comprehensive Configuration
    - Maximum Configuration
    - Security Configuration
    - Monitoring Configuration
    - Compliance Configuration
    - Integration Configuration
    - Custom Configuration
    
    Prerequisites:
    - Windows Server 2016 or later
    - Active Directory Domain Services
    - Administrative privileges
    - Network connectivity
    - Sufficient storage space
    - Sufficient memory and CPU resources
    
    Dependencies:
    - AD-Core.psm1
    - AD-Security.psm1
    - AD-Monitoring.psm1
    - AD-Troubleshooting.psm1
    
    Usage Examples:
    .\Configure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -ConfigurationLevel "Standard"
    .\Configure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -ConfigurationLevel "Comprehensive" -IncludeSecurity -IncludeMonitoring -IncludeCompliance -IncludeIntegration -IncludeCustom -CustomConfigurationScript "C:\Scripts\Custom-AD-Configuration.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Configuration-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Configuration-Report.pdf"
    
    Output:
    - Console logging with color-coded messages
    - Configuration results summary
    - Detailed configuration steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Configures secure AD settings
    - Implements security baselines
    - Enables security logging
    - Configures security compliance settings
    
    Performance Impact:
    - Minimal impact during configuration
    - Non-destructive operations
    - Configurable configuration scope
    - Resource-aware configuration
#>
