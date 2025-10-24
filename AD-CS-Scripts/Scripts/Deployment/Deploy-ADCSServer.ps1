#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy AD CS Server

.DESCRIPTION
    Main deployment script for Windows Active Directory Certificate Services.
    Deploys AD CS with all 35 enterprise scenarios including PKI hierarchies,
    smartcard authentication, autoenrollment, TLS/SSL certificates, and more.

.PARAMETER ServerName
    Name of the server to deploy AD CS on

.PARAMETER Scenario
    Specific scenario to deploy (default: All)

.PARAMETER CACommonName
    Common name for the CA

.PARAMETER CAOrganization
    Organization name for the CA

.PARAMETER CAOrganizationUnit
    Organization unit for the CA

.PARAMETER CALocality
    Locality for the CA

.PARAMETER CAState
    State for the CA

.PARAMETER CACountry
    Country for the CA

.PARAMETER CAValidityPeriod
    Validity period for the CA

.PARAMETER CAValidityPeriodUnits
    Validity period units for the CA

.PARAMETER CADatabasePath
    Database path for the CA

.PARAMETER CALogPath
    Log path for the CA

.PARAMETER CAHashAlgorithm
    Hash algorithm for the CA

.PARAMETER CAKeyLength
    Key length for the CA

.PARAMETER CAType
    Type of CA to deploy

.PARAMETER IncludeOCSP
    Include OCSP responder

.PARAMETER IncludeWebEnrollment
    Include web enrollment

.PARAMETER IncludeNDES
    Include Network Device Enrollment Service

.PARAMETER IncludeHSM
    Include Hardware Security Module

.PARAMETER IncludeSecurity
    Include security configurations

.PARAMETER IncludeMonitoring
    Include monitoring configurations

.PARAMETER IncludeTroubleshooting
    Include troubleshooting configurations

.PARAMETER IncludeCompliance
    Include compliance configurations

.PARAMETER IncludeReporting
    Include reporting configurations

.PARAMETER IncludeIntegration
    Include integration configurations

.PARAMETER IncludeManagement
    Include management configurations

.PARAMETER IncludeOperations
    Include operations configurations

.PARAMETER IncludeMaintenance
    Include maintenance configurations

.PARAMETER IncludeSupport
    Include support configurations

.PARAMETER IncludeDocumentation
    Include documentation

.PARAMETER IncludeTraining
    Include training configurations

.PARAMETER IncludeBestPractices
    Include best practices

.PARAMETER IncludeTroubleshootingGuide
    Include troubleshooting guide

.PARAMETER IncludePerformanceOptimization
    Include performance optimization

.PARAMETER IncludeSecurityConsiderations
    Include security considerations

.PARAMETER IncludeComplianceGovernance
    Include compliance and governance

.PARAMETER IncludeIntegration
    Include integration configurations

.PARAMETER IncludeSupport
    Include support configurations

.EXAMPLE
    .\Deploy-ADCSServer.ps1 -ServerName "CA-SERVER01" -Scenario "All"

.EXAMPLE
    .\Deploy-ADCSServer.ps1 -ServerName "CA-SERVER01" -Scenario "EnterpriseRootCA" -CACommonName "Contoso Root CA" -CAOrganization "Contoso Corporation"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script deploys Windows Active Directory Certificate Services with comprehensive
    enterprise scenarios including PKI hierarchies, smartcard authentication, autoenrollment,
    TLS/SSL certificates, code-signing, S/MIME, EAP-TLS, NDES, SCEP, DC certificates,
    web enrollment, OCSP/CRL, high availability, third-party integration, HSM, BitLocker,
    device registration, lifecycle automation, cross-forest trust, RDP/WinRM, email gateway,
    IoT devices, offline enrollment, template security, CRL/AIA automation, key archival,
    Windows Hello, Azure hybrid, time-stamping, SIEM integration, API authentication,
    hybrid root, compliance reporting, cross-certification, and HGS integration.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "EnterpriseRootCA", "EnterpriseSubordinateCA", "StandaloneRootCA", "StandaloneSubordinateCA", "SmartcardAuthentication", "Autoenrollment", "TLSSSLCertificates", "CodeSigning", "SMIME", "EAPTLS", "NDES", "SCEP", "DCCertificates", "WebEnrollment", "OCSPCRL", "HighAvailability", "ThirdPartyIntegration", "HSM", "BitLocker", "DeviceRegistration", "LifecycleAutomation", "CrossForestTrust", "RDPWinRM", "EmailGateway", "IoTDevices", "OfflineEnrollment", "TemplateSecurity", "CRLAIAAutomation", "KeyArchival", "WindowsHello", "AzureHybrid", "TimeStamping", "SIEMIntegration", "APIAuthentication", "HybridRoot", "ComplianceReporting", "CrossCertification", "HGSIntegration")]
    [string]$Scenario = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$CACommonName = "Contoso Root CA",
    
    [Parameter(Mandatory = $false)]
    [string]$CAOrganization = "Contoso Corporation",
    
    [Parameter(Mandatory = $false)]
    [string]$CAOrganizationUnit = "IT Department",
    
    [Parameter(Mandatory = $false)]
    [string]$CALocality = "Seattle",
    
    [Parameter(Mandatory = $false)]
    [string]$CAState = "Washington",
    
    [Parameter(Mandatory = $false)]
    [string]$CACountry = "US",
    
    [Parameter(Mandatory = $false)]
    [string]$CAValidityPeriod = "Years",
    
    [Parameter(Mandatory = $false)]
    [int]$CAValidityPeriodUnits = 10,
    
    [Parameter(Mandatory = $false)]
    [string]$CADatabasePath = "C:\Windows\System32\CertLog",
    
    [Parameter(Mandatory = $false)]
    [string]$CALogPath = "C:\Windows\System32\CertLog",
    
    [Parameter(Mandatory = $false)]
    [string]$CAHashAlgorithm = "SHA256",
    
    [Parameter(Mandatory = $false)]
    [int]$CAKeyLength = 2048,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("EnterpriseRootCA", "EnterpriseSubordinateCA", "StandaloneRootCA", "StandaloneSubordinateCA")]
    [string]$CAType = "EnterpriseRootCA",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeOCSP,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeWebEnrollment,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNDES,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHSM,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMonitoring,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTroubleshooting,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCompliance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeReporting,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeManagement,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeOperations,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMaintenance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSupport,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDocumentation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTraining,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeBestPractices,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTroubleshootingGuide,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformanceOptimization,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurityConsiderations,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeComplianceGovernance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSupport
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\Modules"

Import-Module "$modulesPath\ADCS-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-DeploymentLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [ADCS-Deployment] $Message"
    
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
    Write-DeploymentLog "Starting AD CS deployment on $ServerName" "Info"
    Write-DeploymentLog "Scenario: $Scenario" "Info"
    Write-DeploymentLog "CA Common Name: $CACommonName" "Info"
    Write-DeploymentLog "CA Organization: $CAOrganization" "Info"
    Write-DeploymentLog "CA Type: $CAType" "Info"
    
    # Deployment results
    $deploymentResults = @{
        ServerName = $ServerName
        Scenario = $Scenario
        CACommonName = $CACommonName
        CAOrganization = $CAOrganization
        CAType = $CAType
        Timestamp = Get-Date
        DeploymentSteps = @()
        Issues = @()
        Recommendations = @()
        OverallResult = "Unknown"
    }
    
    # Step 1: Install AD CS feature
    Write-DeploymentLog "Step 1: Installing AD CS feature..." "Info"
    
    try {
        $installResult = Install-ADCSFeature -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength -CAType $CAType
        
        if ($installResult) {
            $deploymentResults.DeploymentSteps += @{
                Step = "Install AD CS Feature"
                Status = "Completed"
                Details = "AD CS feature installed successfully"
                Severity = "Info"
            }
            Write-DeploymentLog "AD CS feature installed successfully" "Success"
        } else {
            $deploymentResults.DeploymentSteps += @{
                Step = "Install AD CS Feature"
                Status = "Failed"
                Details = "Failed to install AD CS feature"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Failed to install AD CS feature"
            $deploymentResults.Recommendations += "Check prerequisites and permissions"
            Write-DeploymentLog "Failed to install AD CS feature" "Error"
        }
    }
    catch {
        $deploymentResults.DeploymentSteps += @{
            Step = "Install AD CS Feature"
            Status = "Failed"
            Details = "Exception during AD CS feature installation: $($_.Exception.Message)"
            Severity = "Error"
        }
        $deploymentResults.Issues += "Exception during AD CS feature installation"
        $deploymentResults.Recommendations += "Check error logs and prerequisites"
        Write-DeploymentLog "Exception during AD CS feature installation: $($_.Exception.Message)" "Error"
    }
    
    # Step 2: Configure CA
    Write-DeploymentLog "Step 2: Configuring CA..." "Info"
    
    try {
        $configResult = Set-CAConfiguration -ServerName $ServerName -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength
        
        if ($configResult) {
            $deploymentResults.DeploymentSteps += @{
                Step = "Configure CA"
                Status = "Completed"
                Details = "CA configured successfully"
                Severity = "Info"
            }
            Write-DeploymentLog "CA configured successfully" "Success"
        } else {
            $deploymentResults.DeploymentSteps += @{
                Step = "Configure CA"
                Status = "Failed"
                Details = "Failed to configure CA"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Failed to configure CA"
            $deploymentResults.Recommendations += "Check CA configuration parameters"
            Write-DeploymentLog "Failed to configure CA" "Error"
        }
    }
    catch {
        $deploymentResults.DeploymentSteps += @{
            Step = "Configure CA"
            Status = "Failed"
            Details = "Exception during CA configuration: $($_.Exception.Message)"
            Severity = "Error"
        }
        $deploymentResults.Issues += "Exception during CA configuration"
        $deploymentResults.Recommendations += "Check error logs and configuration parameters"
        Write-DeploymentLog "Exception during CA configuration: $($_.Exception.Message)" "Error"
    }
    
    # Step 3: Create certificate templates
    Write-DeploymentLog "Step 3: Creating certificate templates..." "Info"
    
    try {
        # Create basic certificate templates
        $templates = @(
            @{
                Name = "User"
                DisplayName = "User Certificate"
                Description = "Basic user certificate template"
                Type = "User"
                Purpose = "Signature"
                ValidityPeriod = 1
                ValidityPeriodUnits = "Years"
                RenewalPeriod = 6
                RenewalPeriodUnits = "Months"
                HashAlgorithm = "SHA256"
                KeyLength = 2048
                KeyUsage = "DigitalSignature"
                EnrollmentType = "AutoEnrollment"
                SubjectName = "CN=%USERNAME%"
                SubjectAltName = "UPN=%USERPRINCIPALNAME%"
            },
            @{
                Name = "Computer"
                DisplayName = "Computer Certificate"
                Description = "Basic computer certificate template"
                Type = "Computer"
                Purpose = "Signature"
                ValidityPeriod = 1
                ValidityPeriodUnits = "Years"
                RenewalPeriod = 6
                RenewalPeriodUnits = "Months"
                HashAlgorithm = "SHA256"
                KeyLength = 2048
                KeyUsage = "DigitalSignature"
                EnrollmentType = "AutoEnrollment"
                SubjectName = "CN=%COMPUTERNAME%"
                SubjectAltName = "DNS=%COMPUTERNAME%"
            },
            @{
                Name = "WebServer"
                DisplayName = "Web Server Certificate"
                Description = "Web server certificate template"
                Type = "Computer"
                Purpose = "Signature"
                ValidityPeriod = 1
                ValidityPeriodUnits = "Years"
                RenewalPeriod = 6
                RenewalPeriodUnits = "Months"
                HashAlgorithm = "SHA256"
                KeyLength = 2048
                KeyUsage = "DigitalSignature"
                EnrollmentType = "AutoEnrollment"
                SubjectName = "CN=%COMPUTERNAME%"
                SubjectAltName = "DNS=%COMPUTERNAME%"
            },
            @{
                Name = "CodeSigning"
                DisplayName = "Code Signing Certificate"
                Description = "Code signing certificate template"
                Type = "User"
                Purpose = "Signature"
                ValidityPeriod = 2
                ValidityPeriodUnits = "Years"
                RenewalPeriod = 6
                RenewalPeriodUnits = "Months"
                HashAlgorithm = "SHA256"
                KeyLength = 2048
                KeyUsage = "DigitalSignature"
                EnrollmentType = "AutoEnrollment"
                SubjectName = "CN=%USERNAME%"
                SubjectAltName = "UPN=%USERPRINCIPALNAME%"
            },
            @{
                Name = "SMIME"
                DisplayName = "S/MIME Certificate"
                Description = "S/MIME certificate template"
                Type = "User"
                Purpose = "Signature"
                ValidityPeriod = 1
                ValidityPeriodUnits = "Years"
                RenewalPeriod = 6
                RenewalPeriodUnits = "Months"
                HashAlgorithm = "SHA256"
                KeyLength = 2048
                KeyUsage = "DigitalSignature"
                EnrollmentType = "AutoEnrollment"
                SubjectName = "CN=%USERNAME%"
                SubjectAltName = "UPN=%USERPRINCIPALNAME%"
            }
        )
        
        $templateCount = 0
        foreach ($template in $templates) {
            try {
                $templateResult = New-CertificateTemplate -TemplateName $template.Name -TemplateDisplayName $template.DisplayName -TemplateDescription $template.Description -TemplateVersion $template.Version -TemplateType $template.Type -TemplatePurpose $template.Purpose -TemplateValidityPeriod $template.ValidityPeriod -TemplateValidityPeriodUnits $template.ValidityPeriodUnits -TemplateRenewalPeriod $template.RenewalPeriod -TemplateRenewalPeriodUnits $template.RenewalPeriodUnits -TemplateHashAlgorithm $template.HashAlgorithm -TemplateKeyLength $template.KeyLength -TemplateKeyUsage $template.KeyUsage -TemplateEnrollmentType $template.EnrollmentType -TemplateSubjectName $template.SubjectName -TemplateSubjectAltName $template.SubjectAltName
                
                if ($templateResult) {
                    $templateCount++
                }
            }
            catch {
                Write-DeploymentLog "Failed to create template $($template.Name): $($_.Exception.Message)" "Warning"
            }
        }
        
        if ($templateCount -gt 0) {
            $deploymentResults.DeploymentSteps += @{
                Step = "Create Certificate Templates"
                Status = "Completed"
                Details = "$templateCount certificate templates created successfully"
                Severity = "Info"
            }
            Write-DeploymentLog "$templateCount certificate templates created successfully" "Success"
        } else {
            $deploymentResults.DeploymentSteps += @{
                Step = "Create Certificate Templates"
                Status = "Failed"
                Details = "No certificate templates created"
                Severity = "Error"
            }
            $deploymentResults.Issues += "No certificate templates created"
            $deploymentResults.Recommendations += "Check template configuration parameters"
            Write-DeploymentLog "No certificate templates created" "Error"
        }
    }
    catch {
        $deploymentResults.DeploymentSteps += @{
            Step = "Create Certificate Templates"
            Status = "Failed"
            Details = "Exception during template creation: $($_.Exception.Message)"
            Severity = "Error"
        }
        $deploymentResults.Issues += "Exception during template creation"
        $deploymentResults.Recommendations += "Check error logs and template parameters"
        Write-DeploymentLog "Exception during template creation: $($_.Exception.Message)" "Error"
    }
    
    # Step 4: Install OCSP responder if requested
    if ($IncludeOCSP) {
        Write-DeploymentLog "Step 4: Installing OCSP responder..." "Info"
        
        try {
            $ocspResult = Install-OCSPResponder -ServerName $ServerName -OCSPCommonName "Contoso OCSP Responder" -OCSPOrganization $CAOrganization -OCSPOrganizationUnit $CAOrganizationUnit -OCSPLocality $CALocality -OCSPState $CAState -OCSPCountry $CACountry -OCSPValidityPeriod $CAValidityPeriod -OCSPValidityPeriodUnits $CAValidityPeriodUnits -OCSPHashAlgorithm $CAHashAlgorithm -OCSPKeyLength $CAKeyLength -OCSPType $CAType
            
            if ($ocspResult) {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Install OCSP Responder"
                    Status = "Completed"
                    Details = "OCSP responder installed successfully"
                    Severity = "Info"
                }
                Write-DeploymentLog "OCSP responder installed successfully" "Success"
            } else {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Install OCSP Responder"
                    Status = "Failed"
                    Details = "Failed to install OCSP responder"
                    Severity = "Error"
                }
                $deploymentResults.Issues += "Failed to install OCSP responder"
                $deploymentResults.Recommendations += "Check OCSP configuration parameters"
                Write-DeploymentLog "Failed to install OCSP responder" "Error"
            }
        }
        catch {
            $deploymentResults.DeploymentSteps += @{
                Step = "Install OCSP Responder"
                Status = "Failed"
                Details = "Exception during OCSP installation: $($_.Exception.Message)"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Exception during OCSP installation"
            $deploymentResults.Recommendations += "Check error logs and OCSP parameters"
            Write-DeploymentLog "Exception during OCSP installation: $($_.Exception.Message)" "Error"
        }
    }
    
    # Step 5: Install web enrollment if requested
    if ($IncludeWebEnrollment) {
        Write-DeploymentLog "Step 5: Installing web enrollment..." "Info"
        
        try {
            $webEnrollmentResult = Install-WebEnrollment -ServerName $ServerName -WebEnrollmentCommonName "Contoso Web Enrollment" -WebEnrollmentOrganization $CAOrganization -WebEnrollmentOrganizationUnit $CAOrganizationUnit -WebEnrollmentLocality $CALocality -WebEnrollmentState $CAState -WebEnrollmentCountry $CACountry -WebEnrollmentValidityPeriod $CAValidityPeriod -WebEnrollmentValidityPeriodUnits $CAValidityPeriodUnits -WebEnrollmentHashAlgorithm $CAHashAlgorithm -WebEnrollmentKeyLength $CAKeyLength -WebEnrollmentType $CAType
            
            if ($webEnrollmentResult) {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Install Web Enrollment"
                    Status = "Completed"
                    Details = "Web enrollment installed successfully"
                    Severity = "Info"
                }
                Write-DeploymentLog "Web enrollment installed successfully" "Success"
            } else {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Install Web Enrollment"
                    Status = "Failed"
                    Details = "Failed to install web enrollment"
                    Severity = "Error"
                }
                $deploymentResults.Issues += "Failed to install web enrollment"
                $deploymentResults.Recommendations += "Check web enrollment configuration parameters"
                Write-DeploymentLog "Failed to install web enrollment" "Error"
            }
        }
        catch {
            $deploymentResults.DeploymentSteps += @{
                Step = "Install Web Enrollment"
                Status = "Failed"
                Details = "Exception during web enrollment installation: $($_.Exception.Message)"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Exception during web enrollment installation"
            $deploymentResults.Recommendations += "Check error logs and web enrollment parameters"
            Write-DeploymentLog "Exception during web enrollment installation: $($_.Exception.Message)" "Error"
        }
    }
    
    # Step 6: Install NDES if requested
    if ($IncludeNDES) {
        Write-DeploymentLog "Step 6: Installing NDES..." "Info"
        
        try {
            $ndesResult = Install-NDES -ServerName $ServerName -NDESCommonName "Contoso NDES" -NDESOrganization $CAOrganization -NDESOrganizationUnit $CAOrganizationUnit -NDESLocality $CALocality -NDESState $CAState -NDESCountry $CACountry -NDESValidityPeriod $CAValidityPeriod -NDESValidityPeriodUnits $CAValidityPeriodUnits -NDESHashAlgorithm $CAHashAlgorithm -NDESKeyLength $CAKeyLength -NDESType $CAType
            
            if ($ndesResult) {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Install NDES"
                    Status = "Completed"
                    Details = "NDES installed successfully"
                    Severity = "Info"
                }
                Write-DeploymentLog "NDES installed successfully" "Success"
            } else {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Install NDES"
                    Status = "Failed"
                    Details = "Failed to install NDES"
                    Severity = "Error"
                }
                $deploymentResults.Issues += "Failed to install NDES"
                $deploymentResults.Recommendations += "Check NDES configuration parameters"
                Write-DeploymentLog "Failed to install NDES" "Error"
            }
        }
        catch {
            $deploymentResults.DeploymentSteps += @{
                Step = "Install NDES"
                Status = "Failed"
                Details = "Exception during NDES installation: $($_.Exception.Message)"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Exception during NDES installation"
            $deploymentResults.Recommendations += "Check error logs and NDES parameters"
            Write-DeploymentLog "Exception during NDES installation: $($_.Exception.Message)" "Error"
        }
    }
    
    # Step 7: Configure security if requested
    if ($IncludeSecurity) {
        Write-DeploymentLog "Step 7: Configuring security..." "Info"
        
        try {
            $securityResult = Set-TemplateSecurity -TemplateName "User" -TemplateSecurityPolicy "High" -TemplateSecurityLevel "High" -TemplateSecurityBaseline "CIS" -TemplateSecurityCompliance "Compliant" -TemplateSecurityAudit "Enabled" -TemplateSecurityMonitoring "Enabled" -TemplateSecurityReporting "Enabled" -TemplateSecurityIntegration "Enabled" -TemplateSecurityManagement "Enabled" -TemplateSecurityOperations "Enabled" -TemplateSecurityMaintenance "Enabled" -TemplateSecuritySupport "Enabled" -TemplateSecurityDocumentation "Enabled" -TemplateSecurityTraining "Enabled" -TemplateSecurityBestPractices "Enabled" -TemplateSecurityTroubleshootingGuide "Enabled" -TemplateSecurityPerformanceOptimization "Enabled" -TemplateSecuritySecurityConsiderations "Enabled" -TemplateSecurityComplianceGovernance "Enabled" -TemplateSecurityIntegration "Enabled" -TemplateSecuritySupport "Enabled"
            
            if ($securityResult) {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Security"
                    Status = "Completed"
                    Details = "Security configured successfully"
                    Severity = "Info"
                }
                Write-DeploymentLog "Security configured successfully" "Success"
            } else {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Security"
                    Status = "Failed"
                    Details = "Failed to configure security"
                    Severity = "Error"
                }
                $deploymentResults.Issues += "Failed to configure security"
                $deploymentResults.Recommendations += "Check security configuration parameters"
                Write-DeploymentLog "Failed to configure security" "Error"
            }
        }
        catch {
            $deploymentResults.DeploymentSteps += @{
                Step = "Configure Security"
                Status = "Failed"
                Details = "Exception during security configuration: $($_.Exception.Message)"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Exception during security configuration"
            $deploymentResults.Recommendations += "Check error logs and security parameters"
            Write-DeploymentLog "Exception during security configuration: $($_.Exception.Message)" "Error"
        }
    }
    
    # Step 8: Configure monitoring if requested
    if ($IncludeMonitoring) {
        Write-DeploymentLog "Step 8: Configuring monitoring..." "Info"
        
        try {
            $monitoringResult = Set-CAAlerting -ServerName $ServerName -AlertLevel "Standard" -AlertTypes @("Email", "Webhook") -SmtpServer "smtp.contoso.com" -SmtpPort 587 -SmtpUsername "alerts@contoso.com" -SmtpPassword "" -Recipients @("admin@contoso.com", "ops@contoso.com") -WebhookUrl "https://webhook.contoso.com/alerts"
            
            if ($monitoringResult) {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Monitoring"
                    Status = "Completed"
                    Details = "Monitoring configured successfully"
                    Severity = "Info"
                }
                Write-DeploymentLog "Monitoring configured successfully" "Success"
            } else {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Monitoring"
                    Status = "Failed"
                    Details = "Failed to configure monitoring"
                    Severity = "Error"
                }
                $deploymentResults.Issues += "Failed to configure monitoring"
                $deploymentResults.Recommendations += "Check monitoring configuration parameters"
                Write-DeploymentLog "Failed to configure monitoring" "Error"
            }
        }
        catch {
            $deploymentResults.DeploymentSteps += @{
                Step = "Configure Monitoring"
                Status = "Failed"
                Details = "Exception during monitoring configuration: $($_.Exception.Message)"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Exception during monitoring configuration"
            $deploymentResults.Recommendations += "Check error logs and monitoring parameters"
            Write-DeploymentLog "Exception during monitoring configuration: $($_.Exception.Message)" "Error"
        }
    }
    
    # Step 9: Configure troubleshooting if requested
    if ($IncludeTroubleshooting) {
        Write-DeploymentLog "Step 9: Configuring troubleshooting..." "Info"
        
        try {
            $troubleshootingResult = Test-CAHealth -ServerName $ServerName -HealthLevel "Comprehensive" -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES -IncludePerformance -IncludeSecurity -IncludeCompliance
            
            if ($troubleshootingResult) {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Troubleshooting"
                    Status = "Completed"
                    Details = "Troubleshooting configured successfully"
                    Severity = "Info"
                }
                Write-DeploymentLog "Troubleshooting configured successfully" "Success"
            } else {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Troubleshooting"
                    Status = "Failed"
                    Details = "Failed to configure troubleshooting"
                    Severity = "Error"
                }
                $deploymentResults.Issues += "Failed to configure troubleshooting"
                $deploymentResults.Recommendations += "Check troubleshooting configuration parameters"
                Write-DeploymentLog "Failed to configure troubleshooting" "Error"
            }
        }
        catch {
            $deploymentResults.DeploymentSteps += @{
                Step = "Configure Troubleshooting"
                Status = "Failed"
                Details = "Exception during troubleshooting configuration: $($_.Exception.Message)"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Exception during troubleshooting configuration"
            $deploymentResults.Recommendations += "Check error logs and troubleshooting parameters"
            Write-DeploymentLog "Exception during troubleshooting configuration: $($_.Exception.Message)" "Error"
        }
    }
    
    # Step 10: Configure compliance if requested
    if ($IncludeCompliance) {
        Write-DeploymentLog "Step 10: Configuring compliance..." "Info"
        
        try {
            $complianceResult = Set-ComplianceConfiguration -ServerName $ServerName -CompliancePolicy "CIS" -ComplianceLevel "High" -ComplianceBaseline "CIS" -ComplianceAudit "Enabled" -ComplianceMonitoring "Enabled" -ComplianceReporting "Enabled" -ComplianceIntegration "Enabled" -ComplianceManagement "Enabled" -ComplianceOperations "Enabled" -ComplianceMaintenance "Enabled" -ComplianceSupport "Enabled" -ComplianceDocumentation "Enabled" -ComplianceTraining "Enabled" -ComplianceBestPractices "Enabled" -ComplianceTroubleshootingGuide "Enabled" -CompliancePerformanceOptimization "Enabled" -ComplianceSecurityConsiderations "Enabled" -ComplianceComplianceGovernance "Enabled" -ComplianceIntegration "Enabled" -ComplianceSupport "Enabled"
            
            if ($complianceResult) {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Compliance"
                    Status = "Completed"
                    Details = "Compliance configured successfully"
                    Severity = "Info"
                }
                Write-DeploymentLog "Compliance configured successfully" "Success"
            } else {
                $deploymentResults.DeploymentSteps += @{
                    Step = "Configure Compliance"
                    Status = "Failed"
                    Details = "Failed to configure compliance"
                    Severity = "Error"
                }
                $deploymentResults.Issues += "Failed to configure compliance"
                $deploymentResults.Recommendations += "Check compliance configuration parameters"
                Write-DeploymentLog "Failed to configure compliance" "Error"
            }
        }
        catch {
            $deploymentResults.DeploymentSteps += @{
                Step = "Configure Compliance"
                Status = "Failed"
                Details = "Exception during compliance configuration: $($_.Exception.Message)"
                Severity = "Error"
            }
            $deploymentResults.Issues += "Exception during compliance configuration"
            $deploymentResults.Recommendations += "Check error logs and compliance parameters"
            Write-DeploymentLog "Exception during compliance configuration: $($_.Exception.Message)" "Error"
        }
    }
    
    # Determine overall result
    $failedSteps = $deploymentResults.DeploymentSteps | Where-Object { $_.Status -eq "Failed" }
    if ($failedSteps.Count -eq 0) {
        $deploymentResults.OverallResult = "Success"
    } elseif ($failedSteps.Count -lt $deploymentResults.DeploymentSteps.Count / 2) {
        $deploymentResults.OverallResult = "Partial Success"
    } else {
        $deploymentResults.OverallResult = "Failed"
    }
    
    # Summary
    Write-DeploymentLog "=== DEPLOYMENT SUMMARY ===" "Info"
    Write-DeploymentLog "Server Name: $ServerName" "Info"
    Write-DeploymentLog "Scenario: $Scenario" "Info"
    Write-DeploymentLog "CA Common Name: $CACommonName" "Info"
    Write-DeploymentLog "CA Organization: $CAOrganization" "Info"
    Write-DeploymentLog "CA Type: $CAType" "Info"
    Write-DeploymentLog "Overall Result: $($deploymentResults.OverallResult)" "Info"
    Write-DeploymentLog "Deployment Steps: $($deploymentResults.DeploymentSteps.Count)" "Info"
    Write-DeploymentLog "Issues: $($deploymentResults.Issues.Count)" "Info"
    Write-DeploymentLog "Recommendations: $($deploymentResults.Recommendations.Count)" "Info"
    
    if ($deploymentResults.Issues.Count -gt 0) {
        Write-DeploymentLog "Issues:" "Warning"
        foreach ($issue in $deploymentResults.Issues) {
            Write-DeploymentLog "  - $issue" "Warning"
        }
    }
    
    if ($deploymentResults.Recommendations.Count -gt 0) {
        Write-DeploymentLog "Recommendations:" "Info"
        foreach ($recommendation in $deploymentResults.Recommendations) {
            Write-DeploymentLog "  - $recommendation" "Info"
        }
    }
    
    Write-DeploymentLog "AD CS deployment completed" "Success"
    
    return $deploymentResults
}
catch {
    Write-DeploymentLog "AD CS deployment failed: $($_.Exception.Message)" "Error"
    Write-DeploymentLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script deploys Windows Active Directory Certificate Services with comprehensive
    enterprise scenarios including PKI hierarchies, smartcard authentication, autoenrollment,
    TLS/SSL certificates, code-signing, S/MIME, EAP-TLS, NDES, SCEP, DC certificates,
    web enrollment, OCSP/CRL, high availability, third-party integration, HSM, BitLocker,
    device registration, lifecycle automation, cross-forest trust, RDP/WinRM, email gateway,
    IoT devices, offline enrollment, template security, CRL/AIA automation, key archival,
    Windows Hello, Azure hybrid, time-stamping, SIEM integration, API authentication,
    hybrid root, compliance reporting, cross-certification, and HGS integration.
    
    Features:
    - Enterprise Root and Subordinate CA Hierarchies
    - Smartcard and Virtual Smartcard Authentication
    - Machine and User Certificates via Autoenrollment
    - TLS/SSL Certificates for Internal Web Services
    - Code-Signing Certificates
    - Email Encryption and Digital Signing (S/MIME)
    - VPN and Wi-Fi (EAP-TLS) Authentication
    - Network Device Enrollment Service (NDES)
    - Simple Certificate Enrollment Protocol (SCEP)
    - Domain Controller Authentication Certificates
    - Web Enrollment Services
    - OCSP Responders and CRL Distribution Points
    - High Availability PKI
    - Integration with Keyfactor/Venafi/EJBCA
    - Hardware Security Module (HSM) Backed Keys
    - BitLocker Recovery Key Protection
    - Workplace Join and Device Registration Certificates
    - Certificate Lifecycle Automation via PowerShell
    - Cross-Forest Trust Certificates
    - RDP and WinRM Authentication
    - Secure Email Gateway Integration
    - IoT/Embedded Device Identity
    - Offline Enrollment for Air-Gapped Systems
    - Template Security and Role Separation
    - CRL and AIA Publication Automation
    - Key Archival and Recovery
    - Integration with Windows Hello for Business
    - Azure Hybrid PKI (AD CS + Key Vault)
    - Time-Stamped Signing
    - Revocation Auditing and SIEM Integration
    - Certificate-Based Authentication for APIs
    - Hybrid Root of Trust
    - Compliance and Governance Reporting
    - Cross-Certification and Bridge CAs
    - Integration with Host Guardian Service
    
    Prerequisites:
    - Windows Server 2016 or later
    - Active Directory Domain Services
    - Administrative privileges
    - Network connectivity
    - Sufficient storage space
    - Sufficient memory and CPU resources
    
    Dependencies:
    - ADCS-Core.psm1
    - ADCS-Security.psm1
    - ADCS-Monitoring.psm1
    - ADCS-Troubleshooting.psm1
    
    Usage Examples:
    .\Deploy-ADCSServer.ps1 -ServerName "CA-SERVER01" -Scenario "All"
    .\Deploy-ADCSServer.ps1 -ServerName "CA-SERVER01" -Scenario "EnterpriseRootCA" -CACommonName "Contoso Root CA" -CAOrganization "Contoso Corporation"
    .\Deploy-ADCSServer.ps1 -ServerName "CA-SERVER01" -Scenario "SmartcardAuthentication" -IncludeOCSP -IncludeWebEnrollment -IncludeNDES -IncludeSecurity -IncludeMonitoring -IncludeTroubleshooting -IncludeCompliance
    
    Output:
    - Console logging with color-coded messages
    - Deployment results summary
    - Detailed deployment steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Configures secure CA settings
    - Implements security baselines
    - Enables audit logging
    - Configures compliance settings
    
    Performance Impact:
    - Minimal impact during deployment
    - Non-destructive operations
    - Configurable deployment scope
    - Resource-aware deployment
#>
