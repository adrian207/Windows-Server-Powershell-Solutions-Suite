# DHCP PowerShell Scripts - Complete Enterprise Solution

**Author:** Adrian Johnson (adrian207@gmail.com)  
**Version:** 1.0.0  
**Date:** October 2025

## 🎯 Overview

This comprehensive DHCP PowerShell solution provides enterprise-grade Dynamic Host Configuration Protocol (DHCP) management for Windows Server environments. It includes deployment automation, security features, monitoring capabilities, troubleshooting tools, and support for 35+ enterprise scenarios.

## 🚀 Key Features

### **Core DHCP Operations**
- **Server Installation**: Automated DHCP server role installation
- **Scope Management**: Create, configure, and manage DHCP scopes
- **Option Configuration**: Comprehensive DHCP option management
- **Reservation Management**: MAC address-based IP reservations
- **Lease Management**: Active lease monitoring and management

### **High Availability & Failover**
- **DHCP Failover**: Load balancing and hot standby configurations
- **Superscopes**: Multiple logical subnets on physical networks
- **Split Scopes**: Legacy redundancy for isolated networks
- **Disaster Recovery**: Automated backup and restore capabilities

### **Security Features**
- **Server Authorization**: Active Directory authorization
- **DHCP Filtering**: MAC address allow/deny lists
- **Conflict Detection**: IP conflict prevention
- **Audit Logging**: Comprehensive audit trail
- **Rogue Detection**: Unauthorized server detection

### **Monitoring & Analytics**
- **Performance Monitoring**: Real-time performance metrics
- **Health Status**: Comprehensive health checks
- **Alerting**: Configurable alerts for critical events
- **Analytics**: Lease patterns and network insights
- **SIEM Integration**: Event log forwarding

### **Troubleshooting Tools**
- **Comprehensive Diagnostics**: Automated issue detection
- **Automated Repair**: Common issue resolution
- **Configuration Testing**: Validation and compliance checks
- **Event Log Analysis**: Detailed log analysis
- **Troubleshooting Guide**: Built-in help and guidance

## 📁 Project Structure

```
DHCP-Scripts/
├── Modules/
│   ├── DHCP-Core.psm1              # Core DHCP operations
│   ├── DHCP-Security.psm1          # Security features
│   ├── DHCP-Monitoring.psm1        # Monitoring and analytics
│   └── DHCP-Troubleshooting.psm1   # Troubleshooting tools
├── Scripts/
│   ├── Deployment/
│   │   └── Deploy-DHCPServer.ps1   # Complete server deployment
│   ├── Configuration/
│   ├── Security/
│   ├── Monitoring/
│   ├── Troubleshooting/
│   └── Enterprise-Scenarios/
├── Examples/
├── Tests/
└── Documentation/
```

## 🛠️ Installation & Setup

### Prerequisites
- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Active Directory membership (for authorization)

### Quick Start
```powershell
# Import modules
Import-Module ".\Modules\DHCP-Core.psm1" -Force
Import-Module ".\Modules\DHCP-Security.psm1" -Force
Import-Module ".\Modules\DHCP-Monitoring.psm1" -Force
Import-Module ".\Modules\DHCP-Troubleshooting.psm1" -Force

# Deploy complete DHCP server
.\Scripts\Deployment\Deploy-DHCPServer.ps1 -Environment "Production" -ScopeName "Production" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0" -Router "192.168.1.1" -DNSServers @("8.8.8.8", "8.8.4.4") -EnableSecurity -EnableMonitoring
```

## 🎯 Enterprise Scenarios Supported

### **Core Services**
1. **Core IP Address Assignment** - Automatic IP assignment
2. **DHCP with Dynamic DNS (DDNS) Updates** - Automatic hostname registration
3. **DHCP Reservations** - Fixed IP assignments
4. **DHCP Failover** - High availability configurations
5. **DHCP Superscopes** - Multiple logical subnets

### **High Availability**
6. **DHCP Split Scopes** - Legacy redundancy
7. **DHCP Policy-Based Assignment** - Conditional IP assignment
8. **DHCP Option Configuration** - Custom network parameters
9. **PXE Boot and Imaging Integration** - Network boot support
10. **DHCP Network Access Protection** - Quarantine non-compliant devices

### **Automation & Policy**
11. **DHCP with IPAM Integration** - Centralized address management
12. **DHCP Scope Migration** - Zero-downtime migration
13. **DHCP Authorization** - Prevent rogue servers
14. **DHCP Lease Auditing** - Track IP assignments
15. **DHCP for Wireless Networks** - Wi-Fi client management

### **Security & Hybrid Scenarios**
16. **Multi-Site AD Environments** - Regionalized management
17. **DHCP Relay Agent** - Cross-subnet DHCP
18. **DHCP Option 119** - Domain search lists
19. **DHCP for VoIP Phones** - Telephony device provisioning
20. **Virtualized/Cloud Environments** - Hybrid cloud support

### **Advanced Features**
21. **DHCP for IoT Devices** - Sensor and camera networks
22. **Guest and Contractor VLANs** - Segregated addressing
23. **Dynamic VLAN Assignment** - Automated segmentation
24. **DHCP for Remote Access** - VPN client pools
25. **Disaster Recovery Sites** - DR scope mirroring

### **Automation & Integration**
26. **Custom PowerShell Management** - Infrastructure as code
27. **DHCP with 802.1X Integration** - Identity-based policies
28. **IPv6 DHCPv6 Support** - Dual-stack networks
29. **DHCP Snooping Integration** - Switch security
30. **DHCP as Data Source** - Network analytics

### **Specialized Scenarios**
31. **Lab/Staging Environments** - Test network isolation
32. **DHCP Scope-Level ACLs** - MAC-based admission
33. **PXE Security Boot** - Remediation environments
34. **DHCP Option 252** - Proxy auto-discovery
35. **Lease-Based Asset Tracking** - CMDB integration

## 🔧 Core Functions

### **DHCP-Core Module**
```powershell
# Install DHCP server
Install-DHCPServer -IncludeManagementTools

# Create scope
New-DHCPScope -ScopeName "Production" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0"

# Configure options
Set-DHCPOptions -ScopeId "192.168.1.0" -Router "192.168.1.1" -DNSServers @("8.8.8.8", "8.8.4.4")

# Add reservation
Add-DHCPReservation -ScopeId "192.168.1.0" -IPAddress "192.168.1.50" -ClientId "00-11-22-33-44-55" -Name "Server01"

# Enable failover
Enable-DHCPFailover -PartnerServer "DHCP-Server2" -ScopeId "192.168.1.0" -FailoverMode "LoadBalance"

# Get statistics
Get-DHCPStatistics
```

### **DHCP-Security Module**
```powershell
# Authorize server
Authorize-DHCPServer -DomainController "DC01.contoso.com"

# Configure filtering
Set-DHCPFiltering -FilterType "Allow" -MACAddresses @("00-11-22-33-44-55", "00-AA-BB-CC-DD-EE")

# Enable security policies
Enable-DHCPSecurityPolicies -EnableConflictDetection -EnableAuditLogging

# Get security status
Get-DHCPSecurityStatus

# Remove threats
Remove-DHCPThreats -RemoveRogueServers -RemoveSuspiciousLeases
```

### **DHCP-Monitoring Module**
```powershell
# Start monitoring
Start-DHCPMonitoring -MonitoringDuration 60 -LogPath "C:\DHCP\Monitoring"

# Get health status
Get-DHCPHealthStatus

# Configure alerting
Set-DHCPAlerting -AlertTypes @("HighPacketRate", "LowLeaseUtilization") -EmailRecipients @("admin@contoso.com")

# Get analytics
Get-DHCPAnalytics -TimeRange 24
```

### **DHCP-Troubleshooting Module**
```powershell
# Start diagnostics
Start-DHCPDiagnostics -IncludeEventLogs -IncludeConnectivity -LogPath "C:\DHCP\Diagnostics"

# Repair issues
Repair-DHCPIssues -RepairType "All" -BackupPath "C:\DHCP\Backup"

# Test configuration
Test-DHCPConfiguration

# Get troubleshooting guide
Get-DHCPTroubleshootingGuide
```

## 🔒 Security Features

### **Server Authorization**
- Active Directory integration
- Rogue server prevention
- Domain controller validation

### **DHCP Filtering**
- MAC address allow/deny lists
- Vendor class filtering
- Client identifier filtering

### **Security Policies**
- Conflict detection
- Audit logging
- Rogue detection
- Lease validation

### **Access Control**
- Role-based administration
- Granular permissions
- Administrative delegation

## 📊 Monitoring & Analytics

### **Performance Monitoring**
- Real-time performance counters
- Packet rate monitoring
- Queue length tracking
- Response time analysis

### **Health Status**
- Service status monitoring
- Configuration validation
- Scope health checks
- Lease status analysis

### **Alerting**
- Configurable thresholds
- Email notifications
- Event log integration
- SIEM forwarding

### **Analytics**
- Lease pattern analysis
- Client behavior insights
- Network utilization trends
- Performance recommendations

## 🛠️ Troubleshooting

### **Comprehensive Diagnostics**
- Service health checks
- Configuration validation
- Connectivity testing
- Performance analysis

### **Automated Repair**
- Common issue resolution
- Configuration repair
- Service recovery
- Cache management

### **Event Log Analysis**
- DHCP server logs
- System event logs
- Error correlation
- Trend analysis

### **Troubleshooting Guide**
- Common issues and solutions
- Diagnostic steps
- PowerShell commands
- Event log sources

## 📋 Configuration Examples

### **Basic Production Deployment**
```powershell
.\Deploy-DHCPServer.ps1 -Environment "Production" -ScopeName "Production" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0" -Router "192.168.1.1" -DNSServers @("8.8.8.8", "8.8.4.4") -DomainName "contoso.com" -EnableSecurity -EnableMonitoring -EnableAuditLogging
```

### **High Availability Deployment**
```powershell
.\Deploy-DHCPServer.ps1 -Environment "Production" -ScopeName "Production" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0" -Router "192.168.1.1" -DNSServers @("8.8.8.8", "8.8.4.4") -EnableFailover -PartnerServer "DHCP-Server2" -EnableSecurity -EnableMonitoring
```

### **Development Environment**
```powershell
.\Deploy-DHCPServer.ps1 -Environment "Development" -ScopeName "Dev" -StartRange "192.168.10.100" -EndRange "192.168.10.200" -SubnetMask "255.255.255.0" -Router "192.168.10.1" -DNSServers @("192.168.10.10", "192.168.10.11")
```

## 🔧 Advanced Configuration

### **Custom DHCP Options**
```powershell
$customOptions = @{
    66 = "192.168.1.10"  # TFTP Server
    67 = "pxeboot.n12"   # Boot file
    150 = "192.168.1.20" # TFTP Server for VoIP
    176 = "192.168.1.30" # Call Manager
}

Set-DHCPOptions -ScopeId "192.168.1.0" -CustomOptions $customOptions
```

### **Policy-Based Assignment**
```powershell
# Create policy for specific vendor
Add-DhcpServerv4Policy -Name "Cisco Phones" -Condition OR -VendorClass "Cisco Systems, Inc."

# Set policy options
Set-DhcpServerv4OptionValue -PolicyName "Cisco Phones" -OptionId 150 -Value "192.168.1.20"
```

### **Superscope Configuration**
```powershell
# Create superscope
Add-DhcpServerv4Superscope -SuperscopeName "Multi-Subnet" -ScopeId @("192.168.1.0", "192.168.2.0")
```

## 📈 Performance Optimization

### **Lease Duration Tuning**
- **Workstations**: 8 days (default)
- **Mobile Devices**: 1-2 days
- **Servers**: 30 days
- **IoT Devices**: 1 hour

### **Scope Sizing**
- **Small Office**: 50-100 addresses
- **Medium Office**: 200-500 addresses
- **Large Office**: 500-1000 addresses
- **Enterprise**: 1000+ addresses

### **Performance Monitoring**
```powershell
# Monitor performance
Start-DHCPMonitoring -MonitoringDuration 60 -AlertThresholds @{
    HighPacketRate = 1000
    HighQueueLength = 100
    LowLeaseUtilization = 20
    HighDeclineRate = 10
}
```

## 🔍 Troubleshooting Common Issues

### **Service Not Running**
```powershell
# Check service status
Get-Service -Name DHCPServer

# Start service
Start-Service -Name DHCPServer

# Check dependencies
Get-Service -Name DHCPServer -DependentServices
```

### **Server Not Authorized**
```powershell
# Check authorization
Get-DhcpServerConfiguration

# Authorize server
Authorize-DHCPServer -DomainController "DC01.contoso.com"
```

### **No Active Scopes**
```powershell
# List scopes
Get-DhcpServerv4Scope

# Activate scope
Set-DhcpServerv4Scope -ScopeId "192.168.1.0" -State Active
```

### **IP Conflicts**
```powershell
# Check for conflicts
Get-DhcpServerv4Lease | Where-Object { $_.AddressState -eq "Declined" }

# Remove declined leases
Get-DhcpServerv4Lease | Where-Object { $_.AddressState -eq "Declined" } | Remove-DhcpServerv4Lease
```

## 📚 Additional Resources

### **Microsoft Documentation**
- [DHCP Server Overview](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-top)
- [DHCP Failover](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-failover)
- [DHCP Policies](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-policies)

### **PowerShell Cmdlets**
- [Get-DhcpServerv4Scope](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/get-dhcpserverv4scope)
- [Set-DhcpServerv4OptionValue](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/set-dhcpserverv4optionvalue)
- [Add-DhcpServerv4Reservation](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/add-dhcpserverv4reservation)

### **Best Practices**
- Use DHCP reservations for servers and network devices
- Implement DHCP failover for high availability
- Enable audit logging for compliance
- Monitor lease utilization and performance
- Regular backup of DHCP configuration

## 🤝 Contributing

This solution is designed to be modular and extensible. To contribute:

1. Follow PowerShell best practices
2. Include comprehensive error handling
3. Add detailed help documentation
4. Test thoroughly in lab environments
5. Document any new scenarios or features

## 📄 License

This project is provided as-is for educational and enterprise use. Please ensure compliance with your organization's policies and Microsoft licensing requirements.

---

**🎉 The DHCP PowerShell Scripts solution provides enterprise-grade DHCP management with comprehensive automation, security, monitoring, and troubleshooting capabilities!**
