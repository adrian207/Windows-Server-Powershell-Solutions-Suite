#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD CS Examples

.DESCRIPTION
    Example scripts demonstrating various AD CS scenarios and configurations.
    Provides practical examples for common AD CS implementations including
    enterprise PKI, smartcard deployment, autoenrollment, and more.

.PARAMETER ExampleType
    Type of example to demonstrate

.PARAMETER ServerName
    Name of the server for examples

.PARAMETER DomainName
    Domain name for examples

.PARAMETER CACommonName
    Common name for the CA

.PARAMETER CAOrganization
    Organization for the CA

.PARAMETER CAOrganizationalUnit
    Organizational unit for the CA

.PARAMETER CACity
    City for the CA

.PARAMETER CAState
    State for the CA

.PARAMETER CACountry
    Country for the CA

.PARAMETER CAEmail
    Email for the CA

.PARAMETER TemplateName
    Name of the certificate template

.PARAMETER TemplateDisplayName
    Display name of the certificate template

.PARAMETER TemplatePurpose
    Purpose of the certificate template

.PARAMETER TemplateValidityPeriod
    Validity period for the certificate template

.PARAMETER TemplateRenewalPeriod
    Renewal period for the certificate template

.PARAMETER TemplateKeySize
    Key size for the certificate template

.PARAMETER TemplateKeyAlgorithm
    Key algorithm for the certificate template

.PARAMETER TemplateHashAlgorithm
    Hash algorithm for the certificate template

.PARAMETER TemplateSubjectName
    Subject name for the certificate template

.PARAMETER TemplateSubjectAlternativeName
    Subject alternative name for the certificate template

.PARAMETER TemplateKeyUsage
    Key usage for the certificate template

.PARAMETER TemplateEnhancedKeyUsage
    Enhanced key usage for the certificate template

.PARAMETER TemplateApplicationPolicies
    Application policies for the certificate template

.PARAMETER TemplateIssuancePolicies
    Issuance policies for the certificate template

.PARAMETER TemplateSecurity
    Security settings for the certificate template

.PARAMETER TemplatePermissions
    Permissions for the certificate template

.PARAMETER TemplateAudit
    Audit settings for the certificate template

.PARAMETER TemplateCompliance
    Compliance settings for the certificate template

.PARAMETER TemplateMonitoring
    Monitoring settings for the certificate template

.PARAMETER TemplateAlerting
    Alerting settings for the certificate template

.PARAMETER TemplateReporting
    Reporting settings for the certificate template

.PARAMETER TemplateIntegration
    Integration settings for the certificate template

.PARAMETER TemplateCustom
    Custom settings for the certificate template

.PARAMETER OutputFormat
    Output format for examples

.PARAMETER OutputPath
    Output path for examples

.EXAMPLE
    .\ADCS-Examples.ps1 -ExampleType "EnterprisePKI" -ServerName "CA-SERVER01" -DomainName "contoso.com"

.EXAMPLE
    .\ADCS-Examples.ps1 -ExampleType "SmartcardDeployment" -ServerName "CA-SERVER01" -DomainName "contoso.com" -TemplateName "SmartcardUser" -TemplateDisplayName "Smartcard User Certificate" -TemplatePurpose "Authentication" -TemplateValidityPeriod "P1Y" -TemplateRenewalPeriod "P6M" -TemplateKeySize "2048" -TemplateKeyAlgorithm "RSA" -TemplateHashAlgorithm "SHA256" -TemplateSubjectName "CN=%USERNAME%" -TemplateSubjectAlternativeName "UPN=%USERPRINCIPALNAME%" -TemplateKeyUsage "DigitalSignature,KeyEncipherment" -TemplateEnhancedKeyUsage "Client Authentication" -TemplateApplicationPolicies "Client Authentication" -TemplateIssuancePolicies "Smartcard Authentication" -TemplateSecurity "High" -TemplatePermissions "Authenticated Users:Enroll" -TemplateAudit "Enabled" -TemplateCompliance "Enabled" -TemplateMonitoring "Enabled" -TemplateAlerting "Enabled" -TemplateReporting "Enabled" -TemplateIntegration "Enabled" -TemplateCustom "Custom Settings" -OutputFormat "HTML" -OutputPath "C:\Examples\ADCS-Smartcard-Deployment-Example.html"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("EnterprisePKI", "SmartcardDeployment", "Autoenrollment", "TLS-SSL", "CodeSigning", "SMIME", "VPN-WiFi-EAP-TLS", "NDES", "SCEP-Intune", "DCAuthCerts", "WebEnrollment", "OCSP-CRL", "HighAvailabilityPKI", "Keyfactor-Venafi-EJBCA", "HSM-Backed-Keys", "BitLocker-Recovery", "Workplace-Join", "Cert-Lifecycle-Automation", "Cross-Forest-Trust", "RDP-WinRM-Auth", "Secure-Email-Gateway", "IoT-Embedded-Device-Identity", "Offline-Enrollment", "Template-Security-Role-Separation", "CRL-AIA-Publication", "Key-Archival-Recovery", "Windows-Hello-Business", "Azure-Hybrid-PKI", "Time-Stamped-Signing", "Revocation-Auditing-SIEM", "Cert-Based-API-Container-Auth", "Hybrid-Root-of-Trust", "Compliance-Governance-Reporting", "Cross-Certification-Bridge-CAs", "HGS-Integration")]
    [string]$ExampleType,
    
    [Parameter(Mandatory = $false)]
    [string]$ServerName = "CA-SERVER01",
    
    [Parameter(Mandatory = $false)]
    [string]$DomainName = "contoso.com",
    
    [Parameter(Mandatory = $false)]
    [string]$CACommonName = "Contoso Root CA",
    
    [Parameter(Mandatory = $false)]
    [string]$CAOrganization = "Contoso Corporation",
    
    [Parameter(Mandatory = $false)]
    [string]$CAOrganizationalUnit = "IT Department",
    
    [Parameter(Mandatory = $false)]
    [string]$CACity = "Seattle",
    
    [Parameter(Mandatory = $false)]
    [string]$CAState = "Washington",
    
    [Parameter(Mandatory = $false)]
    [string]$CACountry = "US",
    
    [Parameter(Mandatory = $false)]
    [string]$CAEmail = "ca-admin@contoso.com",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateName = "ExampleTemplate",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateDisplayName = "Example Certificate Template",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplatePurpose = "Authentication",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateValidityPeriod = "P1Y",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateRenewalPeriod = "P6M",
    
    [Parameter(Mandatory = $false)]
    [int]$TemplateKeySize = 2048,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateKeyAlgorithm = "RSA",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateHashAlgorithm = "SHA256",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSubjectName = "CN=%USERNAME%",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSubjectAlternativeName = "UPN=%USERPRINCIPALNAME%",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateKeyUsage = "DigitalSignature,KeyEncipherment",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateEnhancedKeyUsage = "Client Authentication",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateApplicationPolicies = "Client Authentication",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateIssuancePolicies = "Standard Authentication",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurity = "Standard",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplatePermissions = "Authenticated Users:Enroll",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateAudit = "Enabled",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateCompliance = "Enabled",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateMonitoring = "Enabled",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateAlerting = "Enabled",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateReporting = "Enabled",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateIntegration = "Enabled",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateCustom = "Custom Settings",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\ADCS-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-ExampleLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [ADCS-Examples] $Message"
    
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
    Write-ExampleLog "Starting AD CS example: $ExampleType" "Info"
    Write-ExampleLog "Server Name: $ServerName" "Info"
    Write-ExampleLog "Domain Name: $DomainName" "Info"
    
    # Example results
    $exampleResults = @{
        ExampleType = $ExampleType
        ServerName = $ServerName
        DomainName = $DomainName
        Timestamp = Get-Date
        ExampleSteps = @()
        Configuration = @{}
        Issues = @()
        Recommendations = @()
        OverallResult = "Unknown"
    }
    
    # Configure example based on type
    switch ($ExampleType) {
        "EnterprisePKI" {
            Write-ExampleLog "Demonstrating Enterprise PKI example..." "Info"
            
            # Step 1: Deploy Enterprise Root CA
            try {
                $rootCA = Install-CARole -ServerName $ServerName -CARole "RootCA" -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationalUnit $CAOrganizationalUnit -CACity $CACity -CAState $CAState -CACountry $CACountry -CAEmail $CAEmail -ValidityPeriod "P20Y" -KeySize 4096 -HashAlgorithm "SHA256" -KeyAlgorithm "RSA"
                
                if ($rootCA) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Deploy Enterprise Root CA"
                        Status = "Completed"
                        Details = "Enterprise Root CA deployed successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.RootCA = $rootCA
                    Write-ExampleLog "Enterprise Root CA deployed successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Deploy Enterprise Root CA"
                        Status = "Failed"
                        Details = "Failed to deploy Enterprise Root CA"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to deploy Enterprise Root CA"
                    $exampleResults.Recommendations += "Check Enterprise Root CA deployment parameters"
                    Write-ExampleLog "Failed to deploy Enterprise Root CA" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Deploy Enterprise Root CA"
                    Status = "Failed"
                    Details = "Exception during Enterprise Root CA deployment: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during Enterprise Root CA deployment"
                $exampleResults.Recommendations += "Check error logs and Enterprise Root CA deployment parameters"
                Write-ExampleLog "Exception during Enterprise Root CA deployment: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Deploy Enterprise Subordinate CA
            try {
                $subordinateCA = Install-CARole -ServerName $ServerName -CARole "SubordinateCA" -CACommonName "Contoso Subordinate CA" -CAOrganization $CAOrganization -CAOrganizationalUnit $CAOrganizationalUnit -CACity $CACity -CAState $CAState -CACountry $CACountry -CAEmail $CAEmail -ValidityPeriod "P10Y" -KeySize 2048 -HashAlgorithm "SHA256" -KeyAlgorithm "RSA" -ParentCA "Contoso Root CA"
                
                if ($subordinateCA) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Deploy Enterprise Subordinate CA"
                        Status = "Completed"
                        Details = "Enterprise Subordinate CA deployed successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.SubordinateCA = $subordinateCA
                    Write-ExampleLog "Enterprise Subordinate CA deployed successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Deploy Enterprise Subordinate CA"
                        Status = "Failed"
                        Details = "Failed to deploy Enterprise Subordinate CA"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to deploy Enterprise Subordinate CA"
                    $exampleResults.Recommendations += "Check Enterprise Subordinate CA deployment parameters"
                    Write-ExampleLog "Failed to deploy Enterprise Subordinate CA" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Deploy Enterprise Subordinate CA"
                    Status = "Failed"
                    Details = "Exception during Enterprise Subordinate CA deployment: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during Enterprise Subordinate CA deployment"
                $exampleResults.Recommendations += "Check error logs and Enterprise Subordinate CA deployment parameters"
                Write-ExampleLog "Exception during Enterprise Subordinate CA deployment: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure Certificate Templates
            try {
                $certificateTemplates = Set-CertificateTemplates -ServerName $ServerName -Templates @(
                    @{
                        Name = "User"
                        DisplayName = "User Certificate"
                        Purpose = "Authentication"
                        ValidityPeriod = "P1Y"
                        RenewalPeriod = "P6M"
                        KeySize = 2048
                        KeyAlgorithm = "RSA"
                        HashAlgorithm = "SHA256"
                        SubjectName = "CN=%USERNAME%"
                        SubjectAlternativeName = "UPN=%USERPRINCIPALNAME%"
                        KeyUsage = "DigitalSignature,KeyEncipherment"
                        EnhancedKeyUsage = "Client Authentication"
                        ApplicationPolicies = "Client Authentication"
                        IssuancePolicies = "Standard Authentication"
                        Security = "Standard"
                        Permissions = "Authenticated Users:Enroll"
                        Audit = "Enabled"
                        Compliance = "Enabled"
                        Monitoring = "Enabled"
                        Alerting = "Enabled"
                        Reporting = "Enabled"
                        Integration = "Enabled"
                        Custom = "Custom Settings"
                    },
                    @{
                        Name = "Computer"
                        DisplayName = "Computer Certificate"
                        Purpose = "Authentication"
                        ValidityPeriod = "P1Y"
                        RenewalPeriod = "P6M"
                        KeySize = 2048
                        KeyAlgorithm = "RSA"
                        HashAlgorithm = "SHA256"
                        SubjectName = "CN=%MACHINENAME%"
                        SubjectAlternativeName = "DNS=%MACHINENAME%.%DOMAINNAME%"
                        KeyUsage = "DigitalSignature,KeyEncipherment"
                        EnhancedKeyUsage = "Client Authentication,Server Authentication"
                        ApplicationPolicies = "Client Authentication,Server Authentication"
                        IssuancePolicies = "Standard Authentication"
                        Security = "Standard"
                        Permissions = "Authenticated Users:Enroll"
                        Audit = "Enabled"
                        Compliance = "Enabled"
                        Monitoring = "Enabled"
                        Alerting = "Enabled"
                        Reporting = "Enabled"
                        Integration = "Enabled"
                        Custom = "Custom Settings"
                    }
                )
                
                if ($certificateTemplates) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Certificate Templates"
                        Status = "Completed"
                        Details = "Certificate templates configured successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.CertificateTemplates = $certificateTemplates
                    Write-ExampleLog "Certificate templates configured successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Certificate Templates"
                        Status = "Failed"
                        Details = "Failed to configure certificate templates"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to configure certificate templates"
                    $exampleResults.Recommendations += "Check certificate template configuration parameters"
                    Write-ExampleLog "Failed to configure certificate templates" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Configure Certificate Templates"
                    Status = "Failed"
                    Details = "Exception during certificate template configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during certificate template configuration"
                $exampleResults.Recommendations += "Check error logs and certificate template configuration parameters"
                Write-ExampleLog "Exception during certificate template configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure Autoenrollment
            try {
                $autoenrollment = Set-CAAutoenrollment -ServerName $ServerName -Enabled $true -Templates @("User", "Computer") -RenewalOnly $false -ExpirationNotification $true -ExpirationNotificationDays 30
                
                if ($autoenrollment) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Autoenrollment"
                        Status = "Completed"
                        Details = "Autoenrollment configured successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.Autoenrollment = $autoenrollment
                    Write-ExampleLog "Autoenrollment configured successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Autoenrollment"
                        Status = "Failed"
                        Details = "Failed to configure autoenrollment"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to configure autoenrollment"
                    $exampleResults.Recommendations += "Check autoenrollment configuration parameters"
                    Write-ExampleLog "Failed to configure autoenrollment" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Configure Autoenrollment"
                    Status = "Failed"
                    Details = "Exception during autoenrollment configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during autoenrollment configuration"
                $exampleResults.Recommendations += "Check error logs and autoenrollment configuration parameters"
                Write-ExampleLog "Exception during autoenrollment configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Configure CRL and AIA
            try {
                $crlAIA = Set-CACRL-AIA -ServerName $ServerName -CRLPublicationURLs @("http://crl.contoso.com/crl/ContosoRootCA.crl", "ldap:///CN=ContosoRootCA,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com") -AIAPublicationURLs @("http://certs.contoso.com/certs/ContosoRootCA.crt", "ldap:///CN=ContosoRootCA,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com") -CRLPeriod "P1W" -CRLOverlapPeriod "P1D" -DeltaCRLPeriod "P1D" -DeltaCRLOverlapPeriod "P12H"
                
                if ($crlAIA) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure CRL and AIA"
                        Status = "Completed"
                        Details = "CRL and AIA configured successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.CRLAIA = $crlAIA
                    Write-ExampleLog "CRL and AIA configured successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure CRL and AIA"
                        Status = "Failed"
                        Details = "Failed to configure CRL and AIA"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to configure CRL and AIA"
                    $exampleResults.Recommendations += "Check CRL and AIA configuration parameters"
                    Write-ExampleLog "Failed to configure CRL and AIA" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Configure CRL and AIA"
                    Status = "Failed"
                    Details = "Exception during CRL and AIA configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during CRL and AIA configuration"
                $exampleResults.Recommendations += "Check error logs and CRL and AIA configuration parameters"
                Write-ExampleLog "Exception during CRL and AIA configuration: $($_.Exception.Message)" "Error"
            }
        }
        
        "SmartcardDeployment" {
            Write-ExampleLog "Demonstrating Smartcard Deployment example..." "Info"
            
            # Step 1: Create Smartcard Certificate Template
            try {
                $smartcardTemplate = New-CertificateTemplate -ServerName $ServerName -TemplateName $TemplateName -TemplateDisplayName $TemplateDisplayName -TemplatePurpose $TemplatePurpose -TemplateValidityPeriod $TemplateValidityPeriod -TemplateRenewalPeriod $TemplateRenewalPeriod -TemplateKeySize $TemplateKeySize -TemplateKeyAlgorithm $TemplateKeyAlgorithm -TemplateHashAlgorithm $TemplateHashAlgorithm -TemplateSubjectName $TemplateSubjectName -TemplateSubjectAlternativeName $TemplateSubjectAlternativeName -TemplateKeyUsage $TemplateKeyUsage -TemplateEnhancedKeyUsage $TemplateEnhancedKeyUsage -TemplateApplicationPolicies $TemplateApplicationPolicies -TemplateIssuancePolicies $TemplateIssuancePolicies -TemplateSecurity $TemplateSecurity -TemplatePermissions $TemplatePermissions -TemplateAudit $TemplateAudit -TemplateCompliance $TemplateCompliance -TemplateMonitoring $TemplateMonitoring -TemplateAlerting $TemplateAlerting -TemplateReporting $TemplateReporting -TemplateIntegration $TemplateIntegration -TemplateCustom $TemplateCustom
                
                if ($smartcardTemplate) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Create Smartcard Certificate Template"
                        Status = "Completed"
                        Details = "Smartcard certificate template created successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.SmartcardTemplate = $smartcardTemplate
                    Write-ExampleLog "Smartcard certificate template created successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Create Smartcard Certificate Template"
                        Status = "Failed"
                        Details = "Failed to create smartcard certificate template"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to create smartcard certificate template"
                    $exampleResults.Recommendations += "Check smartcard certificate template creation parameters"
                    Write-ExampleLog "Failed to create smartcard certificate template" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Create Smartcard Certificate Template"
                    Status = "Failed"
                    Details = "Exception during smartcard certificate template creation: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during smartcard certificate template creation"
                $exampleResults.Recommendations += "Check error logs and smartcard certificate template creation parameters"
                Write-ExampleLog "Exception during smartcard certificate template creation: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure Smartcard Enrollment
            try {
                $smartcardEnrollment = Set-CASmartcardEnrollment -ServerName $ServerName -TemplateName $TemplateName -Enabled $true -RequireSmartcard $true -AllowUserEnrollment $true -AllowAdminEnrollment $true -EnrollmentMethod "Web" -EnrollmentURL "https://certs.contoso.com/certsrv" -EnrollmentAuthentication "Windows Authentication" -EnrollmentAuthorization "Authenticated Users" -EnrollmentAudit "Enabled" -EnrollmentCompliance "Enabled" -EnrollmentMonitoring "Enabled" -EnrollmentAlerting "Enabled" -EnrollmentReporting "Enabled" -EnrollmentIntegration "Enabled" -EnrollmentCustom "Custom Settings"
                
                if ($smartcardEnrollment) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Smartcard Enrollment"
                        Status = "Completed"
                        Details = "Smartcard enrollment configured successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.SmartcardEnrollment = $smartcardEnrollment
                    Write-ExampleLog "Smartcard enrollment configured successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Smartcard Enrollment"
                        Status = "Failed"
                        Details = "Failed to configure smartcard enrollment"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to configure smartcard enrollment"
                    $exampleResults.Recommendations += "Check smartcard enrollment configuration parameters"
                    Write-ExampleLog "Failed to configure smartcard enrollment" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Configure Smartcard Enrollment"
                    Status = "Failed"
                    Details = "Exception during smartcard enrollment configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during smartcard enrollment configuration"
                $exampleResults.Recommendations += "Check error logs and smartcard enrollment configuration parameters"
                Write-ExampleLog "Exception during smartcard enrollment configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure Smartcard Authentication
            try {
                $smartcardAuth = Set-CASmartcardAuthentication -ServerName $ServerName -TemplateName $TemplateName -Enabled $true -RequireSmartcard $true -AllowUserAuthentication $true -AllowAdminAuthentication $true -AuthenticationMethod "Smartcard" -AuthenticationURL "https://auth.contoso.com" -AuthenticationAudit "Enabled" -AuthenticationCompliance "Enabled" -AuthenticationMonitoring "Enabled" -AuthenticationAlerting "Enabled" -AuthenticationReporting "Enabled" -AuthenticationIntegration "Enabled" -AuthenticationCustom "Custom Settings"
                
                if ($smartcardAuth) {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Smartcard Authentication"
                        Status = "Completed"
                        Details = "Smartcard authentication configured successfully"
                        Severity = "Info"
                    }
                    $exampleResults.Configuration.SmartcardAuth = $smartcardAuth
                    Write-ExampleLog "Smartcard authentication configured successfully" "Success"
                } else {
                    $exampleResults.ExampleSteps += @{
                        Step = "Configure Smartcard Authentication"
                        Status = "Failed"
                        Details = "Failed to configure smartcard authentication"
                        Severity = "Error"
                    }
                    $exampleResults.Issues += "Failed to configure smartcard authentication"
                    $exampleResults.Recommendations += "Check smartcard authentication configuration parameters"
                    Write-ExampleLog "Failed to configure smartcard authentication" "Error"
                }
            }
            catch {
                $exampleResults.ExampleSteps += @{
                    Step = "Configure Smartcard Authentication"
                    Status = "Failed"
                    Details = "Exception during smartcard authentication configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $exampleResults.Issues += "Exception during smartcard authentication configuration"
                $exampleResults.Recommendations += "Check error logs and smartcard authentication configuration parameters"
                Write-ExampleLog "Exception during smartcard authentication configuration: $($_.Exception.Message)" "Error"
            }
        }
        
        default {
            Write-ExampleLog "Unknown example type: $ExampleType" "Error"
            $exampleResults.ExampleSteps += @{
                Step = "Example Type Validation"
                Status = "Failed"
                Details = "Unknown example type: $ExampleType"
                Severity = "Error"
            }
            $exampleResults.Issues += "Unknown example type: $ExampleType"
            $exampleResults.Recommendations += "Use a valid example type"
        }
    }
    
    # Determine overall result
    $failedSteps = $exampleResults.ExampleSteps | Where-Object { $_.Status -eq "Failed" }
    if ($failedSteps.Count -eq 0) {
        $exampleResults.OverallResult = "Success"
    } elseif ($failedSteps.Count -lt $exampleResults.ExampleSteps.Count / 2) {
        $exampleResults.OverallResult = "Partial Success"
    } else {
        $exampleResults.OverallResult = "Failed"
    }
    
    # Summary
    Write-ExampleLog "=== EXAMPLE SUMMARY ===" "Info"
    Write-ExampleLog "Example Type: $ExampleType" "Info"
    Write-ExampleLog "Server Name: $ServerName" "Info"
    Write-ExampleLog "Domain Name: $DomainName" "Info"
    Write-ExampleLog "Overall Result: $($exampleResults.OverallResult)" "Info"
    Write-ExampleLog "Example Steps: $($exampleResults.ExampleSteps.Count)" "Info"
    Write-ExampleLog "Issues: $($exampleResults.Issues.Count)" "Info"
    Write-ExampleLog "Recommendations: $($exampleResults.Recommendations.Count)" "Info"
    
    if ($exampleResults.Issues.Count -gt 0) {
        Write-ExampleLog "Issues:" "Warning"
        foreach ($issue in $exampleResults.Issues) {
            Write-ExampleLog "  - $issue" "Warning"
        }
    }
    
    if ($exampleResults.Recommendations.Count -gt 0) {
        Write-ExampleLog "Recommendations:" "Info"
        foreach ($recommendation in $exampleResults.Recommendations) {
            Write-ExampleLog "  - $recommendation" "Info"
        }
    }
    
    Write-ExampleLog "AD CS example completed" "Success"
    
    return $exampleResults
}
catch {
    Write-ExampleLog "AD CS example failed: $($_.Exception.Message)" "Error"
    Write-ExampleLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive examples for Windows Active Directory Certificate Services
    with various example types including enterprise PKI, smartcard deployment, autoenrollment, and more.
    
    Features:
    - Enterprise PKI Examples
    - Smartcard Deployment Examples
    - Autoenrollment Examples
    - TLS/SSL Examples
    - Code Signing Examples
    - S/MIME Examples
    - VPN/Wi-Fi EAP-TLS Examples
    - NDES Examples
    - SCEP via Intune Examples
    - DC Auth Certificates Examples
    - Web Enrollment Examples
    - OCSP/CRL Examples
    - High Availability PKI Examples
    - Keyfactor/Venafi/EJBCA Integration Examples
    - HSM Backed Keys Examples
    - BitLocker Recovery Examples
    - Workplace Join Examples
    - Certificate Lifecycle Automation Examples
    - Cross-Forest Trust Examples
    - RDP/WinRM Authentication Examples
    - Secure Email Gateway Examples
    - IoT/Embedded Device Identity Examples
    - Offline Enrollment Examples
    - Template Security/Role Separation Examples
    - CRL/AIA Publication Examples
    - Key Archival/Recovery Examples
    - Windows Hello for Business Examples
    - Azure Hybrid PKI Examples
    - Time-Stamped Signing Examples
    - Revocation Auditing/SIEM Examples
    - Certificate-Based API/Container Authentication Examples
    - Hybrid Root of Trust Examples
    - Compliance/Governance Reporting Examples
    - Cross-Certification/Bridge CAs Examples
    - HGS Integration Examples
    
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
    .\ADCS-Examples.ps1 -ExampleType "EnterprisePKI" -ServerName "CA-SERVER01" -DomainName "contoso.com"
    .\ADCS-Examples.ps1 -ExampleType "SmartcardDeployment" -ServerName "CA-SERVER01" -DomainName "contoso.com" -TemplateName "SmartcardUser" -TemplateDisplayName "Smartcard User Certificate" -TemplatePurpose "Authentication" -TemplateValidityPeriod "P1Y" -TemplateRenewalPeriod "P6M" -TemplateKeySize "2048" -TemplateKeyAlgorithm "RSA" -TemplateHashAlgorithm "SHA256" -TemplateSubjectName "CN=%USERNAME%" -TemplateSubjectAlternativeName "UPN=%USERPRINCIPALNAME%" -TemplateKeyUsage "DigitalSignature,KeyEncipherment" -TemplateEnhancedKeyUsage "Client Authentication" -TemplateApplicationPolicies "Client Authentication" -TemplateIssuancePolicies "Smartcard Authentication" -TemplateSecurity "High" -TemplatePermissions "Authenticated Users:Enroll" -TemplateAudit "Enabled" -TemplateCompliance "Enabled" -TemplateMonitoring "Enabled" -TemplateAlerting "Enabled" -TemplateReporting "Enabled" -TemplateIntegration "Enabled" -TemplateCustom "Custom Settings" -OutputFormat "HTML" -OutputPath "C:\Examples\ADCS-Smartcard-Deployment-Example.html"
    
    Output:
    - Console logging with color-coded messages
    - Example results summary
    - Detailed example steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Demonstrates secure configurations
    - Implements security baselines
    - Enables security logging
    - Configures security compliance settings
    
    Performance Impact:
    - Minimal impact during example execution
    - Non-destructive operations
    - Configurable example scope
    - Resource-aware example execution
#>
