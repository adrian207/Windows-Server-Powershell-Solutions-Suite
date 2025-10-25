# Windows Failover Clustering PowerShell Solution

**Author:** Adrian Johnson (adrian207@gmail.com)  
**Version:** 1.0.0  
**Date:** October 2025

A comprehensive, modular, and portable PowerShell solution for implementing, configuring, and managing Windows Failover Clustering in enterprise environments. This solution covers all 35 enterprise scenarios for high availability, disaster recovery, and clustered services.

## 🚀 **Overview**

Windows Failover Clustering provides high availability and disaster recovery for critical workloads. This PowerShell solution provides complete automation for cluster deployment, configuration, management, monitoring, and troubleshooting across all enterprise scenarios.

### **Key Features**

- **35 Enterprise Scenarios** - Complete coverage of all clustering use cases
- **Modular Design** - Reusable PowerShell modules for different clustering functions
- **High Availability** - Built-in HA patterns and best practices
- **Disaster Recovery** - Multi-site clustering and replication
- **Comprehensive Monitoring** - Health checks, performance metrics, and alerting
- **Troubleshooting Tools** - Diagnostic tools and automated repair functions
- **Production Ready** - Tested and validated for enterprise deployment

## 📋 **Table of Contents**

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Modules](#modules)
6. [Scripts](#scripts)
7. [Enterprise Scenarios](#enterprise-scenarios)
8. [Examples](#examples)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)
11. [Best Practices](#best-practices)
12. [Support](#support)

## 🏗️ **Architecture**

### **Module Structure**

```
Failover-Clustering-Scripts/
├── Modules/
│   ├── Cluster-Core.psm1              # Core clustering operations and management
│   ├── Cluster-Security.psm1          # Security features and access control
│   ├── Cluster-Monitoring.psm1       # Health monitoring and performance metrics
│   └── Cluster-Troubleshooting.psm1   # Diagnostics, repair, and recovery operations
├── Scripts/
│   ├── Deployment/
│   │   └── Deploy-FailoverCluster.ps1 # Main cluster deployment script
│   ├── Configuration/
│   │   └── Configure-Cluster.ps1      # Configuration management
│   ├── Security/
│   │   └── Secure-Cluster.ps1        # Security implementation
│   ├── Monitoring/
│   │   └── Monitor-Cluster.ps1       # Monitoring and alerting
│   ├── Troubleshooting/
│   │   └── Troubleshoot-Cluster.ps1   # Troubleshooting tools
│   └── Enterprise-Scenarios/
│       └── Deploy-ClusterEnterpriseScenarios.ps1  # All 35 enterprise scenarios
├── Examples/
│   └── Cluster-Examples.ps1          # Comprehensive examples and demonstrations
├── Tests/
│   └── Test-Cluster.ps1              # Comprehensive test suite using Pester
├── Documentation/
│   └── Cluster-Documentation.md     # Comprehensive documentation
└── README.md                        # This file
```

### **Core Components**

#### **Cluster-Core Module**
- **Cluster Management**: Create, configure, and manage failover clusters
- **Node Management**: Add, remove, and manage cluster nodes
- **Resource Management**: Manage clustered resources and roles
- **Quorum Management**: Configure quorum and witness settings
- **Basic Operations**: Status checks, health monitoring, basic diagnostics

#### **Cluster-Security Module**
- **Access Control**: Cluster security and permissions management
- **Authentication**: Kerberos and certificate-based authentication
- **Authorization**: Role-based access control for cluster management
- **Audit Logging**: Comprehensive audit and compliance logging
- **Security Baselines**: Security configuration and hardening

#### **Cluster-Monitoring Module**
- **Health Monitoring**: Continuous health checks and status reporting
- **Performance Metrics**: Cluster and resource performance monitoring
- **Event Analysis**: Cluster event log analysis and alerting
- **Capacity Planning**: Resource utilization and growth planning
- **Alerting**: Email, webhook, SNMP, Slack, Teams notifications

#### **Cluster-Troubleshooting Module**
- **Diagnostics**: Comprehensive health and configuration testing
- **Event Analysis**: Deep log analysis with pattern recognition
- **Performance Troubleshooting**: Performance issue identification and resolution
- **Repair Operations**: Automated repair and recovery procedures
- **Troubleshooting Guidance**: Step-by-step issue resolution guides

## 🚀 **Installation**

### **Prerequisites**

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Failover Clustering feature installed
- Network connectivity between cluster nodes

### **Installation Steps**

1. **Download the Failover Clustering PowerShell Solution**
   ```powershell
   # Clone or download the Failover-Clustering-Scripts directory
   # Ensure all files are in the correct directory structure
   ```

2. **Verify Prerequisites**
   ```powershell
   # Check PowerShell version
   $PSVersionTable.PSVersion
   
   # Check Windows version
   Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
   
   # Check Failover Clustering feature
   Get-WindowsFeature -Name "Failover-Clustering"
   ```

3. **Import Modules**
   ```powershell
   # Import all clustering modules
   Import-Module ".\Modules\Cluster-Core.psm1" -Force
   Import-Module ".\Modules\Cluster-Security.psm1" -Force
   Import-Module ".\Modules\Cluster-Monitoring.psm1" -Force
   Import-Module ".\Modules\Cluster-Troubleshooting.psm1" -Force
   ```

4. **Run Initial Tests**
   ```powershell
   # Run basic functionality tests
   .\Tests\Test-Cluster.ps1 -TestType "Unit"
   ```

## 🚀 **Quick Start**

### **Basic Cluster Deployment**

1. **Deploy Failover Cluster**
   ```powershell
   .\Scripts\Deployment\Deploy-FailoverCluster.ps1 -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeAndFileShareMajority"
   ```

2. **Configure Cluster**
   ```powershell
   .\Scripts\Configuration\Configure-Cluster.ps1 -ClusterName "PROD-CLUSTER" -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"
   ```

3. **Apply Security Baseline**
   ```powershell
   .\Scripts\Security\Secure-Cluster.ps1 -ClusterName "PROD-CLUSTER" -SecurityLevel "High" -ComplianceStandard "CIS"
   ```

4. **Setup Monitoring**
   ```powershell
   .\Scripts\Monitoring\Monitor-Cluster.ps1 -ClusterName "PROD-CLUSTER" -MonitoringLevel "Advanced" -AlertMethods @("Email", "Webhook")
   ```

### **Enterprise Scenario Deployment**

Deploy specific enterprise scenarios:

```powershell
# Deploy High Availability File Services
.\Scripts\Enterprise-Scenarios\Deploy-ClusterEnterpriseScenarios.ps1 -ScenarioNumber 1 -ClusterName "PROD-CLUSTER"

# Deploy Highly Available Hyper-V VMs
.\Scripts\Enterprise-Scenarios\Deploy-ClusterEnterpriseScenarios.ps1 -ScenarioNumber 2 -ClusterName "PROD-CLUSTER"

# Deploy SQL Server Always-On FCI
.\Scripts\Enterprise-Scenarios\Deploy-ClusterEnterpriseScenarios.ps1 -ScenarioNumber 3 -ClusterName "PROD-CLUSTER"
```

## 📚 **Modules**

### **Cluster-Core Module**

#### **Core Functions**

- **New-FailoverCluster**: Create new failover cluster
- **Add-ClusterNode**: Add node to cluster
- **Remove-ClusterNode**: Remove node from cluster
- **Get-ClusterStatus**: Get cluster status and health
- **Set-ClusterQuorum**: Configure cluster quorum
- **New-ClusterResource**: Create clustered resource
- **Start-ClusterResource**: Start clustered resource
- **Stop-ClusterResource**: Stop clustered resource

#### **Usage Examples**

```powershell
# Create new cluster
New-FailoverCluster -ClusterName "PROD-CLUSTER" -Nodes @("NODE01", "NODE02") -QuorumType "NodeAndFileShareMajority"

# Add node to cluster
Add-ClusterNode -ClusterName "PROD-CLUSTER" -NodeName "NODE03"

# Get cluster status
Get-ClusterStatus -ClusterName "PROD-CLUSTER"

# Configure quorum
Set-ClusterQuorum -ClusterName "PROD-CLUSTER" -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"
```

### **Cluster-Security Module**

#### **Security Functions**

- **Set-ClusterSecurityBaseline**: Apply security baselines
- **Set-ClusterAccessControl**: Configure cluster access control
- **Set-ClusterAuthentication**: Configure authentication methods
- **Enable-ClusterAuditLogging**: Enable comprehensive audit logging
- **Set-ClusterPermissions**: Configure cluster permissions
- **Test-ClusterSecurity**: Test cluster security configuration

#### **Usage Examples**

```powershell
# Apply security baseline
Set-ClusterSecurityBaseline -ClusterName "PROD-CLUSTER" -BaselineName "CIS-High" -ComplianceStandard "CIS"

# Configure access control
Set-ClusterAccessControl -ClusterName "PROD-CLUSTER" -AccessModel "RoleBased" -SecurityLevel "High"

# Enable audit logging
Enable-ClusterAuditLogging -ClusterName "PROD-CLUSTER" -LogLevel "Detailed" -RetentionDays 90
```

### **Cluster-Monitoring Module**

#### **Monitoring Functions**

- **Get-ClusterHealthStatus**: Get comprehensive cluster health status
- **Get-ClusterPerformanceMetrics**: Get cluster performance metrics
- **Get-ClusterEventAnalysis**: Analyze cluster event logs
- **Set-ClusterMonitoring**: Configure cluster monitoring
- **Set-ClusterAlerting**: Configure alerting methods
- **Get-ClusterCapacityPlanning**: Generate capacity planning reports

#### **Usage Examples**

```powershell
# Get cluster health status
Get-ClusterHealthStatus -ClusterName "PROD-CLUSTER" -IncludeDetails

# Get performance metrics
Get-ClusterPerformanceMetrics -ClusterName "PROD-CLUSTER" -MetricType "All"

# Configure alerting
Set-ClusterAlerting -ClusterName "PROD-CLUSTER" -AlertMethods @("Email", "Webhook") -Recipients @("admin@contoso.com")
```

### **Cluster-Troubleshooting Module**

#### **Troubleshooting Functions**

- **Test-ClusterDiagnostics**: Run comprehensive cluster diagnostics
- **Test-ClusterConfiguration**: Test cluster configuration
- **Get-ClusterEventAnalysis**: Analyze cluster event logs for issues
- **Repair-ClusterService**: Repair cluster service issues
- **Get-ClusterTroubleshootingGuide**: Get troubleshooting guidance
- **Test-ClusterConnectivity**: Test cluster connectivity

#### **Usage Examples**

```powershell
# Run cluster diagnostics
Test-ClusterDiagnostics -ClusterName "PROD-CLUSTER" -DiagnosticLevel "Comprehensive"

# Test cluster configuration
Test-ClusterConfiguration -ClusterName "PROD-CLUSTER" -TestType "All"

# Get troubleshooting guide
Get-ClusterTroubleshootingGuide -IssueType "Quorum" -Severity "High"
```

## 🎯 **Enterprise Scenarios**

### **All 35 Enterprise Scenarios**

1. **High Availability for File Services** - Scale-Out File Server (SOFS) and clustered shares
2. **Highly Available Hyper-V Virtual Machines** - VM clustering with CSV storage
3. **SQL Server Always-On Failover Cluster Instances (FCI)** - Database-level high availability
4. **Cluster Shared Volumes (CSV)** - Shared storage across all nodes
5. **Stretch Clusters / Multi-Site Disaster Recovery** - Cross-datacenter high availability
6. **Cluster-Aware Updating (CAU)** - Zero-downtime patching
7. **Failover Clustering with Storage Spaces Direct (S2D)** - Hyper-converged infrastructure
8. **Highly Available DHCP / DNS** - Network core services redundancy
9. **Clustered Print Servers** - Print service high availability
10. **File Server for Application Data** - Back-end file shares for applications
11. **iSCSI Target Server Clustering** - Redundant block storage
12. **NFS Cluster for UNIX/Linux Clients** - High availability NFS shares
13. **Active/Active Load Balancing** - Multiple active nodes (SOFS)
14. **Active/Passive Role Failover** - Classic HA model
15. **Heartbeat and Witness Configuration** - Cluster quorum management
16. **Cluster Validation Wizard** - Configuration validation
17. **Cloud Witness for Hybrid Clusters** - Azure Storage as quorum witness
18. **VM Resiliency with Fault Domains** - Placement awareness
19. **Guest Clustering** - Cluster applications inside VMs
20. **Cluster-Aware Backup and Recovery** - VSS in clusters
21. **High-Availability Certificate Authority** - Cluster subordinate/issuing CAs
22. **Hyper-V Replica + Failover Cluster Integration** - Combined replication and clustering
23. **Application Availability via Generic Roles** - HA for non-cluster-aware applications
24. **Clustered MSMQ (Message Queuing)** - Message queue availability
25. **File Server for User Profile Disks (UPDs) and FSLogix** - Profile disk clustering
26. **Failover Clustering for Keyfactor or CA Database** - PKI database protection
27. **PowerShell and REST API Cluster Management** - Infrastructure-as-Code
28. **Multi-Subnet Clusters** - Geographic HA across subnets
29. **Rolling Upgrades Across OS Versions** - Seamless OS upgrades
30. **SIEM and Monitoring Integration** - Cluster health forwarding
31. **Cluster-Aware Storage Replica** - Storage replication between sites
32. **Quorum File Share Witness in Edge Environments** - Lightweight witness
33. **Hyper-V Shielded VM Cluster Integration** - HGS integration with clustering
34. **Tiered Application Clusters** - Multi-tiered app clustering
35. **Test/Dev Sandbox for HA Workloads** - Lab cluster validation

### **Scenario Categories**

#### **Core High Availability (1-10)**
- File Services, Hyper-V VMs, SQL Server FCI, CSV, Stretch Clusters
- CAU, S2D, DHCP/DNS, Print Servers, Application Data

#### **Storage and Infrastructure (11-20)**
- iSCSI Target, NFS Cluster, Load Balancing, Quorum Management
- Validation, Cloud Witness, Fault Domains, Guest Clustering, Backup

#### **Advanced Enterprise (21-30)**
- Certificate Authority, Hyper-V Replica, Generic Roles, MSMQ
- Profile Disks, PKI Database, PowerShell Management, Multi-Subnet

#### **Specialized Scenarios (31-35)**
- Storage Replica, Edge Witness, Shielded VMs, Tiered Apps, Test/Dev

## 📖 **Examples**

### **Basic Examples**

```powershell
# Create basic cluster
New-FailoverCluster -ClusterName "TEST-CLUSTER" -Nodes @("NODE01", "NODE02")

# Add clustered file share
New-ClusterResource -ClusterName "TEST-CLUSTER" -ResourceName "FileShare" -ResourceType "File Server"

# Configure quorum
Set-ClusterQuorum -ClusterName "TEST-CLUSTER" -QuorumType "NodeMajority"
```

### **Advanced Examples**

```powershell
# Deploy Scale-Out File Server
New-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "SOFS" -ResourceType "Scale-Out File Server"

# Configure Storage Spaces Direct
Enable-StorageSpacesDirect -ClusterName "PROD-CLUSTER" -CacheMode "WriteBack"

# Setup Cluster-Aware Updating
Enable-ClusterAwareUpdating -ClusterName "PROD-CLUSTER" -UpdateMode "Automatic"
```

### **Enterprise Examples**

```powershell
# Deploy stretch cluster
New-FailoverCluster -ClusterName "STRETCH-CLUSTER" -Nodes @("SITE1-NODE01", "SITE1-NODE02", "SITE2-NODE01", "SITE2-NODE02") -QuorumType "NodeAndFileShareMajority"

# Configure cloud witness
Set-ClusterQuorum -ClusterName "PROD-CLUSTER" -QuorumType "NodeAndCloudMajority" -CloudWitnessAccountName "AzureStorageAccount"

# Deploy SQL Server FCI
New-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "SQL-FCI" -ResourceType "SQL Server" -Dependencies @("SQL-Disk", "SQL-Network")
```

## 🧪 **Testing**

### **Test Suite**

The solution includes a comprehensive test suite using Pester:

```powershell
# Run all tests
.\Tests\Test-Cluster.ps1 -TestType "All" -ClusterName "TEST-CLUSTER"

# Run unit tests
.\Tests\Test-Cluster.ps1 -TestType "Unit"

# Run integration tests
.\Tests\Test-Cluster.ps1 -TestType "Integration" -ClusterName "TEST-CLUSTER"

# Run performance tests
.\Tests\Test-Cluster.ps1 -TestType "Performance" -ClusterName "TEST-CLUSTER"
```

### **Test Categories**

- **Unit Tests**: Module loading, function availability, parameter validation
- **Integration Tests**: Cluster operations, resource management, quorum configuration
- **Performance Tests**: Performance metrics, response times, scalability
- **Security Tests**: Security configuration, access control, audit logging
- **Enterprise Tests**: Scenario deployment, advanced configurations

## 🔧 **Troubleshooting**

### **Common Issues**

#### **Cluster Service Issues**
```powershell
# Check cluster service status
Get-Service -Name "ClusSvc"

# Restart cluster service
Restart-Service -Name "ClusSvc"

# Check cluster event logs
Get-WinEvent -LogName "System" -FilterHashtable @{ID=1205,1206,1207,1208,1209,1210}
```

#### **Quorum Issues**
```powershell
# Check quorum status
Get-ClusterQuorum -ClusterName "PROD-CLUSTER"

# Test quorum witness
Test-ClusterQuorum -ClusterName "PROD-CLUSTER"

# Configure quorum witness
Set-ClusterQuorum -ClusterName "PROD-CLUSTER" -QuorumType "NodeAndFileShareMajority" -WitnessShare "\\DC01\ClusterWitness"
```

#### **Resource Failover Issues**
```powershell
# Check resource status
Get-ClusterResource -ClusterName "PROD-CLUSTER"

# Test resource failover
Move-ClusterResource -ClusterName "PROD-CLUSTER" -ResourceName "FileShare" -Node "NODE02"

# Check resource dependencies
Get-ClusterResourceDependency -ClusterName "PROD-CLUSTER" -ResourceName "FileShare"
```

### **Troubleshooting Tools**

```powershell
# Run comprehensive diagnostics
.\Scripts\Troubleshooting\Troubleshoot-Cluster.ps1 -ClusterName "PROD-CLUSTER" -DiagnosticLevel "Comprehensive"

# Test cluster configuration
Test-ClusterConfiguration -ClusterName "PROD-CLUSTER" -TestType "All"

# Get troubleshooting guide
Get-ClusterTroubleshootingGuide -IssueType "Quorum" -Severity "High"
```

## 📋 **Best Practices**

### **Cluster Design**

1. **Node Configuration**
   - Use identical hardware for cluster nodes
   - Ensure sufficient network connectivity
   - Configure proper storage connectivity
   - Plan for maintenance windows

2. **Quorum Configuration**
   - Use appropriate quorum type for environment
   - Configure witness for odd number of nodes
   - Test quorum witness connectivity
   - Document quorum configuration

3. **Network Configuration**
   - Use dedicated cluster networks
   - Configure proper network priorities
   - Test network connectivity
   - Monitor network performance

### **Security Best Practices**

1. **Access Control**
   - Use role-based access control
   - Limit cluster administration rights
   - Enable audit logging
   - Regular security assessments

2. **Authentication**
   - Use Kerberos authentication
   - Configure certificate-based authentication
   - Implement multi-factor authentication
   - Regular credential rotation

### **Monitoring Best Practices**

1. **Health Monitoring**
   - Monitor cluster health continuously
   - Set up appropriate alerting
   - Regular health assessments
   - Performance monitoring

2. **Capacity Planning**
   - Regular capacity assessments
   - Growth planning
   - Resource optimization
   - Performance tuning

## 📞 **Support**

### **Getting Help**

1. **Documentation**
   - Review this comprehensive documentation
   - Check the Cluster-Documentation.md file
   - Review example scripts
   - Check troubleshooting guides

2. **Examples and Testing**
   ```powershell
   # Run examples
   .\Examples\Cluster-Examples.ps1 -ExampleType "All" -Interactive
   
   # Run tests
   .\Tests\Test-Cluster.ps1 -TestType "All" -Verbose
   ```

3. **Troubleshooting**
   ```powershell
   # Run diagnostics
   .\Scripts\Troubleshooting\Troubleshoot-Cluster.ps1 -ClusterName "PROD-CLUSTER" -DiagnosticLevel "Comprehensive"
   
   # Get troubleshooting guide
   Get-ClusterTroubleshootingGuide -IssueType "All" -Severity "High"
   ```

### **Contact Information**

**Author:** Adrian Johnson  
**Email:** adrian207@gmail.com  
**Version:** 1.0.0  
**Date:** October 2025

### **Contributing**

1. **Code Quality**
   - Follow PowerShell best practices
   - Use approved PowerShell verbs
   - Include comprehensive help
   - Add error handling

2. **Testing**
   - Add unit tests for new functions
   - Test integration scenarios
   - Validate error handling
   - Document test cases

3. **Documentation**
   - Update this documentation
   - Add examples for new features
   - Update troubleshooting guides
   - Maintain change logs

## 📄 **License**

This Failover Clustering PowerShell Solution is provided as-is for educational and operational purposes. Please ensure compliance with your organization's policies and applicable regulations when using this solution.

---

**Ready for Enterprise Deployment** 🚀
