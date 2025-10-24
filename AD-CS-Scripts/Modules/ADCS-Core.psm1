#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD CS Core Module

.DESCRIPTION
    Core PowerShell module for Windows Active Directory Certificate Services operations.
    Provides essential functions for CA management, certificate templates, enrollment, and revocation.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Module variables
$script:ModuleName = "ADCS-Core"
$script:ModuleVersion = "1.0.0"

# Logging function
function Write-ADCSLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [$script:ModuleName] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# CA Management Functions
function Install-ADCSFeature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
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
        [string]$CAType = "EnterpriseRootCA"
    )
    
    try {
        Write-ADCSLog "Installing AD CS feature on $ServerName" "Info"
        
        # Install AD CS feature
        Install-WindowsFeature -Name "ADCS-Cert-Authority" -IncludeManagementTools -ComputerName $ServerName
        
        # Install CA
        Install-AdcsCertificationAuthority -CACommonName $CACommonName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CADatabasePath $CADatabasePath -CALogPath $CALogPath -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength -CAType $CAType -Force
        
        Write-ADCSLog "AD CS feature installed successfully on $ServerName" "Success"
        return $true
    }
    catch {
        Write-ADCSLog "Failed to install AD CS feature on $ServerName`: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-CAStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    
    try {
        Write-ADCSLog "Getting CA status for $ServerName" "Info"
        
        $ca = Get-CertificationAuthority -ComputerName $ServerName
        $caStatus = @{
            ServerName = $ServerName
            CACommonName = $ca.CACommonName
            CAStatus = $ca.Status
            CAVersion = $ca.Version
            CADatabasePath = $ca.DatabasePath
            CALogPath = $ca.LogPath
            CAValidityPeriod = $ca.ValidityPeriod
            CAValidityPeriodUnits = $ca.ValidityPeriodUnits
            CAHashAlgorithm = $ca.HashAlgorithm
            CAKeyLength = $ca.KeyLength
            CAType = $ca.Type
            Timestamp = Get-Date
        }
        
        Write-ADCSLog "CA status retrieved successfully for $ServerName" "Success"
        return $caStatus
    }
    catch {
        Write-ADCSLog "Failed to get CA status for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Set-CAConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$CACommonName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganization,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganizationUnit,
        
        [Parameter(Mandatory = $false)]
        [string]$CALocality,
        
        [Parameter(Mandatory = $false)]
        [string]$CAState,
        
        [Parameter(Mandatory = $false)]
        [string]$CACountry,
        
        [Parameter(Mandatory = $false)]
        [string]$CAValidityPeriod,
        
        [Parameter(Mandatory = $false)]
        [int]$CAValidityPeriodUnits,
        
        [Parameter(Mandatory = $false)]
        [string]$CADatabasePath,
        
        [Parameter(Mandatory = $false)]
        [string]$CALogPath,
        
        [Parameter(Mandatory = $false)]
        [string]$CAHashAlgorithm,
        
        [Parameter(Mandatory = $false)]
        [int]$CAKeyLength
    )
    
    try {
        Write-ADCSLog "Configuring CA on $ServerName" "Info"
        
        # Get current CA configuration
        $ca = Get-CertificationAuthority -ComputerName $ServerName
        
        # Update CA configuration
        if ($CACommonName) { $ca.CACommonName = $CACommonName }
        if ($CAOrganization) { $ca.CAOrganization = $CAOrganization }
        if ($CAOrganizationUnit) { $ca.CAOrganizationUnit = $CAOrganizationUnit }
        if ($CALocality) { $ca.CALocality = $CALocality }
        if ($CAState) { $ca.CAState = $CAState }
        if ($CACountry) { $ca.CACountry = $CACountry }
        if ($CAValidityPeriod) { $ca.CAValidityPeriod = $CAValidityPeriod }
        if ($CAValidityPeriodUnits) { $ca.CAValidityPeriodUnits = $CAValidityPeriodUnits }
        if ($CADatabasePath) { $ca.DatabasePath = $CADatabasePath }
        if ($CALogPath) { $ca.LogPath = $CALogPath }
        if ($CAHashAlgorithm) { $ca.HashAlgorithm = $CAHashAlgorithm }
        if ($CAKeyLength) { $ca.KeyLength = $CAKeyLength }
        
        Write-ADCSLog "CA configuration updated successfully on $ServerName" "Success"
        return $true
    }
    catch {
        Write-ADCSLog "Failed to configure CA on $ServerName`: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Certificate Template Functions
function New-CertificateTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateDisplayName,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateDescription,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateVersion = "3",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateType = "User",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplatePurpose = "Signature",
        
        [Parameter(Mandatory = $false)]
        [int]$TemplateValidityPeriod = 1,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateValidityPeriodUnits = "Years",
        
        [Parameter(Mandatory = $false)]
        [int]$TemplateRenewalPeriod = 6,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateRenewalPeriodUnits = "Months",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateHashAlgorithm = "SHA256",
        
        [Parameter(Mandatory = $false)]
        [int]$TemplateKeyLength = 2048,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateKeyUsage = "DigitalSignature",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateEnrollmentType = "AutoEnrollment",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateSubjectName = "CN=%USERNAME%",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateSubjectAltName = "UPN=%USERPRINCIPALNAME%",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateIssuancePolicy = "All",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateApplicationPolicy = "All",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateEnrollmentPolicy = "All",
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateSecurityPolicy = "All"
    )
    
    try {
        Write-ADCSLog "Creating certificate template: $TemplateName" "Info"
        
        # Create certificate template
        $template = New-CertificateTemplate -Name $TemplateName -DisplayName $TemplateDisplayName -Description $TemplateDescription -Version $TemplateVersion -Type $TemplateType -Purpose $TemplatePurpose -ValidityPeriod $TemplateValidityPeriod -ValidityPeriodUnits $TemplateValidityPeriodUnits -RenewalPeriod $TemplateRenewalPeriod -RenewalPeriodUnits $TemplateRenewalPeriodUnits -HashAlgorithm $TemplateHashAlgorithm -KeyLength $TemplateKeyLength -KeyUsage $TemplateKeyUsage -EnrollmentType $TemplateEnrollmentType -SubjectName $TemplateSubjectName -SubjectAltName $TemplateSubjectAltName -IssuancePolicy $TemplateIssuancePolicy -ApplicationPolicy $TemplateApplicationPolicy -EnrollmentPolicy $TemplateEnrollmentPolicy -SecurityPolicy $TemplateSecurityPolicy
        
        Write-ADCSLog "Certificate template created successfully: $TemplateName" "Success"
        return $template
    }
    catch {
        Write-ADCSLog "Failed to create certificate template $TemplateName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Get-CertificateTemplate {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TemplateName
    )
    
    try {
        Write-ADCSLog "Getting certificate template: $TemplateName" "Info"
        
        if ($TemplateName) {
            $template = Get-CertificateTemplate -Name $TemplateName
        } else {
            $template = Get-CertificateTemplate
        }
        
        Write-ADCSLog "Certificate template retrieved successfully: $TemplateName" "Success"
        return $template
    }
    catch {
        Write-ADCSLog "Failed to get certificate template $TemplateName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Set-CertificateTemplate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateDisplayName,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateDescription,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateVersion,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateType,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplatePurpose,
        
        [Parameter(Mandatory = $false)]
        [int]$TemplateValidityPeriod,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateValidityPeriodUnits,
        
        [Parameter(Mandatory = $false)]
        [int]$TemplateRenewalPeriod,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateRenewalPeriodUnits,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateHashAlgorithm,
        
        [Parameter(Mandatory = $false)]
        [int]$TemplateKeyLength,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateKeyUsage,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateEnrollmentType,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateSubjectName,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateSubjectAltName,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateIssuancePolicy,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateApplicationPolicy,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateEnrollmentPolicy,
        
        [Parameter(Mandatory = $false)]
        [string]$TemplateSecurityPolicy
    )
    
    try {
        Write-ADCSLog "Updating certificate template: $TemplateName" "Info"
        
        # Get current template
        $template = Get-CertificateTemplate -Name $TemplateName
        
        # Update template properties
        if ($TemplateDisplayName) { $template.DisplayName = $TemplateDisplayName }
        if ($TemplateDescription) { $template.Description = $TemplateDescription }
        if ($TemplateVersion) { $template.Version = $TemplateVersion }
        if ($TemplateType) { $template.Type = $TemplateType }
        if ($TemplatePurpose) { $template.Purpose = $TemplatePurpose }
        if ($TemplateValidityPeriod) { $template.ValidityPeriod = $TemplateValidityPeriod }
        if ($TemplateValidityPeriodUnits) { $template.ValidityPeriodUnits = $TemplateValidityPeriodUnits }
        if ($TemplateRenewalPeriod) { $template.RenewalPeriod = $TemplateRenewalPeriod }
        if ($TemplateRenewalPeriodUnits) { $template.RenewalPeriodUnits = $TemplateRenewalPeriodUnits }
        if ($TemplateHashAlgorithm) { $template.HashAlgorithm = $TemplateHashAlgorithm }
        if ($TemplateKeyLength) { $template.KeyLength = $TemplateKeyLength }
        if ($TemplateKeyUsage) { $template.KeyUsage = $TemplateKeyUsage }
        if ($TemplateEnrollmentType) { $template.EnrollmentType = $TemplateEnrollmentType }
        if ($TemplateSubjectName) { $template.SubjectName = $TemplateSubjectName }
        if ($TemplateSubjectAltName) { $template.SubjectAltName = $TemplateSubjectAltName }
        if ($TemplateIssuancePolicy) { $template.IssuancePolicy = $TemplateIssuancePolicy }
        if ($TemplateApplicationPolicy) { $template.ApplicationPolicy = $TemplateApplicationPolicy }
        if ($TemplateEnrollmentPolicy) { $template.EnrollmentPolicy = $TemplateEnrollmentPolicy }
        if ($TemplateSecurityPolicy) { $template.SecurityPolicy = $TemplateSecurityPolicy }
        
        Write-ADCSLog "Certificate template updated successfully: $TemplateName" "Success"
        return $template
    }
    catch {
        Write-ADCSLog "Failed to update certificate template $TemplateName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Certificate Enrollment Functions
function Request-Certificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateName,
        
        [Parameter(Mandatory = $false)]
        [string]$SubjectName,
        
        [Parameter(Mandatory = $false)]
        [string]$SubjectAltName,
        
        [Parameter(Mandatory = $false)]
        [string]$KeyUsage,
        
        [Parameter(Mandatory = $false)]
        [string]$KeyLength = "2048",
        
        [Parameter(Mandatory = $false)]
        [string]$HashAlgorithm = "SHA256",
        
        [Parameter(Mandatory = $false)]
        [string]$EnrollmentType = "AutoEnrollment",
        
        [Parameter(Mandatory = $false)]
        [string]$CACommonName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAComputerName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganization,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganizationUnit,
        
        [Parameter(Mandatory = $false)]
        [string]$CALocality,
        
        [Parameter(Mandatory = $false)]
        [string]$CAState,
        
        [Parameter(Mandatory = $false)]
        [string]$CACountry,
        
        [Parameter(Mandatory = $false)]
        [string]$CAValidityPeriod = "Years",
        
        [Parameter(Mandatory = $false)]
        [int]$CAValidityPeriodUnits = 1,
        
        [Parameter(Mandatory = $false)]
        [string]$CAHashAlgorithm = "SHA256",
        
        [Parameter(Mandatory = $false)]
        [int]$CAKeyLength = 2048,
        
        [Parameter(Mandatory = $false)]
        [string]$CAType = "EnterpriseRootCA"
    )
    
    try {
        Write-ADCSLog "Requesting certificate for template: $TemplateName" "Info"
        
        # Request certificate
        $certificate = Request-Certificate -TemplateName $TemplateName -SubjectName $SubjectName -SubjectAltName $SubjectAltName -KeyUsage $KeyUsage -KeyLength $KeyLength -HashAlgorithm $HashAlgorithm -EnrollmentType $EnrollmentType -CACommonName $CACommonName -CAComputerName $CAComputerName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength -CAType $CAType
        
        Write-ADCSLog "Certificate requested successfully for template: $TemplateName" "Success"
        return $certificate
    }
    catch {
        Write-ADCSLog "Failed to request certificate for template $TemplateName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

function Get-Certificate {
    param(
        [Parameter(Mandatory = $false)]
        [string]$TemplateName,
        
        [Parameter(Mandatory = $false)]
        [string]$SubjectName,
        
        [Parameter(Mandatory = $false)]
        [string]$SubjectAltName,
        
        [Parameter(Mandatory = $false)]
        [string]$KeyUsage,
        
        [Parameter(Mandatory = $false)]
        [string]$KeyLength,
        
        [Parameter(Mandatory = $false)]
        [string]$HashAlgorithm,
        
        [Parameter(Mandatory = $false)]
        [string]$EnrollmentType,
        
        [Parameter(Mandatory = $false)]
        [string]$CACommonName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAComputerName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganization,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganizationUnit,
        
        [Parameter(Mandatory = $false)]
        [string]$CALocality,
        
        [Parameter(Mandatory = $false)]
        [string]$CAState,
        
        [Parameter(Mandatory = $false)]
        [string]$CACountry,
        
        [Parameter(Mandatory = $false)]
        [string]$CAValidityPeriod,
        
        [Parameter(Mandatory = $false)]
        [int]$CAValidityPeriodUnits,
        
        [Parameter(Mandatory = $false)]
        [string]$CAHashAlgorithm,
        
        [Parameter(Mandatory = $false)]
        [int]$CAKeyLength,
        
        [Parameter(Mandatory = $false)]
        [string]$CAType
    )
    
    try {
        Write-ADCSLog "Getting certificate for template: $TemplateName" "Info"
        
        # Get certificate
        $certificate = Get-Certificate -TemplateName $TemplateName -SubjectName $SubjectName -SubjectAltName $SubjectAltName -KeyUsage $KeyUsage -KeyLength $KeyLength -HashAlgorithm $HashAlgorithm -EnrollmentType $EnrollmentType -CACommonName $CACommonName -CAComputerName $CAComputerName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength -CAType $CAType
        
        Write-ADCSLog "Certificate retrieved successfully for template: $TemplateName" "Success"
        return $certificate
    }
    catch {
        Write-ADCSLog "Failed to get certificate for template $TemplateName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Certificate Revocation Functions
function Revoke-Certificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificateSerialNumber,
        
        [Parameter(Mandatory = $false)]
        [string]$RevocationReason = "Unspecified",
        
        [Parameter(Mandatory = $false)]
        [string]$CACommonName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAComputerName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganization,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganizationUnit,
        
        [Parameter(Mandatory = $false)]
        [string]$CALocality,
        
        [Parameter(Mandatory = $false)]
        [string]$CAState,
        
        [Parameter(Mandatory = $false)]
        [string]$CACountry,
        
        [Parameter(Mandatory = $false)]
        [string]$CAValidityPeriod,
        
        [Parameter(Mandatory = $false)]
        [int]$CAValidityPeriodUnits,
        
        [Parameter(Mandatory = $false)]
        [string]$CAHashAlgorithm,
        
        [Parameter(Mandatory = $false)]
        [int]$CAKeyLength,
        
        [Parameter(Mandatory = $false)]
        [string]$CAType
    )
    
    try {
        Write-ADCSLog "Revoking certificate: $CertificateSerialNumber" "Info"
        
        # Revoke certificate
        Revoke-Certificate -CertificateSerialNumber $CertificateSerialNumber -RevocationReason $RevocationReason -CACommonName $CACommonName -CAComputerName $CAComputerName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength -CAType $CAType
        
        Write-ADCSLog "Certificate revoked successfully: $CertificateSerialNumber" "Success"
        return $true
    }
    catch {
        Write-ADCSLog "Failed to revoke certificate $CertificateSerialNumber`: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-CertificateRevocationList {
    param(
        [Parameter(Mandatory = $false)]
        [string]$CACommonName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAComputerName,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganization,
        
        [Parameter(Mandatory = $false)]
        [string]$CAOrganizationUnit,
        
        [Parameter(Mandatory = $false)]
        [string]$CALocality,
        
        [Parameter(Mandatory = $false)]
        [string]$CAState,
        
        [Parameter(Mandatory = $false)]
        [string]$CACountry,
        
        [Parameter(Mandatory = $false)]
        [string]$CAValidityPeriod,
        
        [Parameter(Mandatory = $false)]
        [int]$CAValidityPeriodUnits,
        
        [Parameter(Mandatory = $false)]
        [string]$CAHashAlgorithm,
        
        [Parameter(Mandatory = $false)]
        [int]$CAKeyLength,
        
        [Parameter(Mandatory = $false)]
        [string]$CAType
    )
    
    try {
        Write-ADCSLog "Getting certificate revocation list" "Info"
        
        # Get CRL
        $crl = Get-CertificateRevocationList -CACommonName $CACommonName -CAComputerName $CAComputerName -CAOrganization $CAOrganization -CAOrganizationUnit $CAOrganizationUnit -CALocality $CALocality -CAState $CAState -CACountry $CACountry -CAValidityPeriod $CAValidityPeriod -CAValidityPeriodUnits $CAValidityPeriodUnits -CAHashAlgorithm $CAHashAlgorithm -CAKeyLength $CAKeyLength -CAType $CAType
        
        Write-ADCSLog "Certificate revocation list retrieved successfully" "Success"
        return $crl
    }
    catch {
        Write-ADCSLog "Failed to get certificate revocation list`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# OCSP Configuration Functions
function Install-OCSPResponder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPCommonName = "Contoso OCSP Responder",
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPOrganization = "Contoso Corporation",
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPOrganizationUnit = "IT Department",
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPLocality = "Seattle",
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPState = "Washington",
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPCountry = "US",
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPValidityPeriod = "Years",
        
        [Parameter(Mandatory = $false)]
        [int]$OCSPValidityPeriodUnits = 5,
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPHashAlgorithm = "SHA256",
        
        [Parameter(Mandatory = $false)]
        [int]$OCSPKeyLength = 2048,
        
        [Parameter(Mandatory = $false)]
        [string]$OCSPType = "EnterpriseRootCA"
    )
    
    try {
        Write-ADCSLog "Installing OCSP responder on $ServerName" "Info"
        
        # Install OCSP responder
        Install-AdcsOnlineResponder -CACommonName $OCSPCommonName -CAOrganization $OCSPOrganization -CAOrganizationUnit $OCSPOrganizationUnit -CALocality $OCSPLocality -CAState $OCSPState -CACountry $OCSPCountry -CAValidityPeriod $OCSPValidityPeriod -CAValidityPeriodUnits $OCSPValidityPeriodUnits -CAHashAlgorithm $OCSPHashAlgorithm -CAKeyLength $OCSPKeyLength -CAType $OCSPType -Force
        
        Write-ADCSLog "OCSP responder installed successfully on $ServerName" "Success"
        return $true
    }
    catch {
        Write-ADCSLog "Failed to install OCSP responder on $ServerName`: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-OCSPStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    
    try {
        Write-ADCSLog "Getting OCSP status for $ServerName" "Info"
        
        $ocsp = Get-AdcsOnlineResponder -ComputerName $ServerName
        $ocspStatus = @{
            ServerName = $ServerName
            OCSPCommonName = $ocsp.CACommonName
            OCSPStatus = $ocsp.Status
            OCSPVersion = $ocsp.Version
            OCSPDatabasePath = $ocsp.DatabasePath
            OCSPLogPath = $ocsp.LogPath
            OCSPValidityPeriod = $ocsp.ValidityPeriod
            OCSPValidityPeriodUnits = $ocsp.ValidityPeriodUnits
            OCSPHashAlgorithm = $ocsp.HashAlgorithm
            OCSPKeyLength = $ocsp.KeyLength
            OCSPType = $ocsp.Type
            Timestamp = Get-Date
        }
        
        Write-ADCSLog "OCSP status retrieved successfully for $ServerName" "Success"
        return $ocspStatus
    }
    catch {
        Write-ADCSLog "Failed to get OCSP status for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Web Enrollment Functions
function Install-WebEnrollment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentCommonName = "Contoso Web Enrollment",
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentOrganization = "Contoso Corporation",
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentOrganizationUnit = "IT Department",
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentLocality = "Seattle",
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentState = "Washington",
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentCountry = "US",
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentValidityPeriod = "Years",
        
        [Parameter(Mandatory = $false)]
        [int]$WebEnrollmentValidityPeriodUnits = 5,
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentHashAlgorithm = "SHA256",
        
        [Parameter(Mandatory = $false)]
        [int]$WebEnrollmentKeyLength = 2048,
        
        [Parameter(Mandatory = $false)]
        [string]$WebEnrollmentType = "EnterpriseRootCA"
    )
    
    try {
        Write-ADCSLog "Installing web enrollment on $ServerName" "Info"
        
        # Install web enrollment
        Install-AdcsWebEnrollment -CACommonName $WebEnrollmentCommonName -CAOrganization $WebEnrollmentOrganization -CAOrganizationUnit $WebEnrollmentOrganizationUnit -CALocality $WebEnrollmentLocality -CAState $WebEnrollmentState -CACountry $WebEnrollmentCountry -CAValidityPeriod $WebEnrollmentValidityPeriod -CAValidityPeriodUnits $WebEnrollmentValidityPeriodUnits -CAHashAlgorithm $WebEnrollmentHashAlgorithm -CAKeyLength $WebEnrollmentKeyLength -CAType $WebEnrollmentType -Force
        
        Write-ADCSLog "Web enrollment installed successfully on $ServerName" "Success"
        return $true
    }
    catch {
        Write-ADCSLog "Failed to install web enrollment on $ServerName`: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-WebEnrollmentStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    
    try {
        Write-ADCSLog "Getting web enrollment status for $ServerName" "Info"
        
        $webEnrollment = Get-AdcsWebEnrollment -ComputerName $ServerName
        $webEnrollmentStatus = @{
            ServerName = $ServerName
            WebEnrollmentCommonName = $webEnrollment.CACommonName
            WebEnrollmentStatus = $webEnrollment.Status
            WebEnrollmentVersion = $webEnrollment.Version
            WebEnrollmentDatabasePath = $webEnrollment.DatabasePath
            WebEnrollmentLogPath = $webEnrollment.LogPath
            WebEnrollmentValidityPeriod = $webEnrollment.ValidityPeriod
            WebEnrollmentValidityPeriodUnits = $webEnrollment.ValidityPeriodUnits
            WebEnrollmentHashAlgorithm = $webEnrollment.HashAlgorithm
            WebEnrollmentKeyLength = $webEnrollment.KeyLength
            WebEnrollmentType = $webEnrollment.Type
            Timestamp = Get-Date
        }
        
        Write-ADCSLog "Web enrollment status retrieved successfully for $ServerName" "Success"
        return $webEnrollmentStatus
    }
    catch {
        Write-ADCSLog "Failed to get web enrollment status for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# NDES Configuration Functions
function Install-NDES {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$NDESCommonName = "Contoso NDES",
        
        [Parameter(Mandatory = $false)]
        [string]$NDESOrganization = "Contoso Corporation",
        
        [Parameter(Mandatory = $false)]
        [string]$NDESOrganizationUnit = "IT Department",
        
        [Parameter(Mandatory = $false)]
        [string]$NDESLocality = "Seattle",
        
        [Parameter(Mandatory = $false)]
        [string]$NDESState = "Washington",
        
        [Parameter(Mandatory = $false)]
        [string]$NDESCountry = "US",
        
        [Parameter(Mandatory = $false)]
        [string]$NDESValidityPeriod = "Years",
        
        [Parameter(Mandatory = $false)]
        [int]$NDESValidityPeriodUnits = 5,
        
        [Parameter(Mandatory = $false)]
        [string]$NDESHashAlgorithm = "SHA256",
        
        [Parameter(Mandatory = $false)]
        [int]$NDESKeyLength = 2048,
        
        [Parameter(Mandatory = $false)]
        [string]$NDESType = "EnterpriseRootCA"
    )
    
    try {
        Write-ADCSLog "Installing NDES on $ServerName" "Info"
        
        # Install NDES
        Install-AdcsNetworkDeviceEnrollmentService -CACommonName $NDESCommonName -CAOrganization $NDESOrganization -CAOrganizationUnit $NDESOrganizationUnit -CALocality $NDESLocality -CAState $NDESState -CACountry $NDESCountry -CAValidityPeriod $NDESValidityPeriod -CAValidityPeriodUnits $NDESValidityPeriodUnits -CAHashAlgorithm $NDESHashAlgorithm -CAKeyLength $NDESKeyLength -CAType $NDESType -Force
        
        Write-ADCSLog "NDES installed successfully on $ServerName" "Success"
        return $true
    }
    catch {
        Write-ADCSLog "Failed to install NDES on $ServerName`: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-NDESStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    
    try {
        Write-ADCSLog "Getting NDES status for $ServerName" "Info"
        
        $ndes = Get-AdcsNetworkDeviceEnrollmentService -ComputerName $ServerName
        $ndesStatus = @{
            ServerName = $ServerName
            NDESCommonName = $ndes.CACommonName
            NDESStatus = $ndes.Status
            NDESVersion = $ndes.Version
            NDESDatabasePath = $ndes.DatabasePath
            NDESLogPath = $ndes.LogPath
            NDESValidityPeriod = $ndes.ValidityPeriod
            NDESValidityPeriodUnits = $ndes.ValidityPeriodUnits
            NDESHashAlgorithm = $ndes.HashAlgorithm
            NDESKeyLength = $ndes.KeyLength
            NDESType = $ndes.Type
            Timestamp = Get-Date
        }
        
        Write-ADCSLog "NDES status retrieved successfully for $ServerName" "Success"
        return $ndesStatus
    }
    catch {
        Write-ADCSLog "Failed to get NDES status for $ServerName`: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Install-ADCSFeature',
    'Get-CAStatus',
    'Set-CAConfiguration',
    'New-CertificateTemplate',
    'Get-CertificateTemplate',
    'Set-CertificateTemplate',
    'Request-Certificate',
    'Get-Certificate',
    'Revoke-Certificate',
    'Get-CertificateRevocationList',
    'Install-OCSPResponder',
    'Get-OCSPStatus',
    'Install-WebEnrollment',
    'Get-WebEnrollmentStatus',
    'Install-NDES',
    'Get-NDESStatus'
)
