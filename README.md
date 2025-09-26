# OpenShift Cluster Health Report Generator

A comprehensive bash script that generates detailed HTML health reports for OpenShift clusters, providing insights into cluster status, security compliance, and operational health with intelligent placement validation and actionable recommendations.

## Quick Feature Overview

This script performs **17 comprehensive health checks** covering:
- 🔒 **Security**: FIPS compliance, etcd/IPSec encryption, certificates, OAuth
- 🌐 **Networking**: Pod networks, ingress controllers, connectivity analysis  
- 💾 **Storage**: Storage classes, ODF/Ceph health, capacity planning
- 🔧 **Operations**: Cluster operators, updates, monitoring, backups
- 📊 **Infrastructure**: Node details, Machine Config Pools, resource utilization

**Key Capabilities:**
- SSH-based node validation for FIPS and NTP compliance
- Smart ingress placement analysis with actionable recommendations
- Complete OpenShift Data Foundation (ODF) health assessment
- Airgapped vs connected environment detection
- Professional HTML reports with responsive design and copy-ready commands

## Features

### Security & Compliance Checks
- **FIPS Compliance**: Validates FIPS mode across all cluster nodes with SSH connectivity and detailed per-node analysis
- **etcd Encryption**: Monitors etcd encryption configuration, key rotation status, and reencryption verification
- **IPSec Encryption**: Checks OVN-Kubernetes IPSec configuration for pod-to-pod encryption
- **Certificate Authority**: Validates API server and ingress certificates, CA configuration, and expiry tracking
- **OAuth Authentication**: Analyzes identity provider configuration, OAuth pod health, and authentication setup

### Infrastructure & Networking
- **NTP Synchronization**: Checks time synchronization status across all nodes with chronyd service monitoring
- **Pod Network Details**: Comprehensive network configuration analysis including CIDR ranges, MTU, and plugin details
- **Ingress Controller**: Advanced placement validation with smart detection and HA recommendations
- **Node Details**: Complete node inventory with roles, taints, labels, and Machine Config Pool status
- **Cluster Connectivity**: Detects airgapped vs connected environments with mirror registry analysis

### Storage & Data Management
- **Storage Classes**: Analyzes all storage classes, CSI drivers, provisioners, and backend storage types
- **OpenShift Data Foundation (ODF)**: Complete ODF health check including Ceph cluster, NooBaa, and MCG status
- **Storage Capacity**: Monitors storage utilization, PV/PVC counts, and capacity planning metrics
- **Backup Status**: etcd backup verification, OADP operator status, and backup schedule monitoring

### Operations & Monitoring
- **Cluster Operators**: Health status of all cluster operators with degradation detection and version tracking
- **Update Service**: OpenShift update configuration, available updates, and channel management
- **AlertManager**: Alert routing configuration, receiver setup, and notification channel validation
- **Loki Logging**: Log aggregation status, tenant configuration, and retention policy analysis

### Advanced Analysis Features
- **Smart Placement Detection**: Prioritizes actual pod placement over configuration for accurate status reporting
- **Multiple Node Selector Patterns**: Supports infra, infrastructure, worker, and complex matchLabels configurations
- **Toleration Analysis**: Detects taint tolerations for proper node scheduling and dedicated infrastructure
- **NodeAffinity Support**: Handles complex node affinity rules and scheduling constraints
- **Replica Optimization**: Intelligent HA recommendations based on cluster topology and available nodes

### Report Features
- **Professional HTML Output**: Modern, responsive design with gradient styling and interactive elements
- **Real-time Status Indicators**: Color-coded status badges with detailed health metrics
- **Actionable Commands**: Copy-ready oc patch commands with proper syntax highlighting
- **Comprehensive Metrics**: Detailed data collection with robust error handling and retry logic
- **Timestamp Tracking**: Report generation time and individual module execution timestamps
- **Export Capabilities**: Self-contained HTML reports for sharing and archival

## Prerequisites

### Required Tools
- **OpenShift CLI (oc)**: Version 4.10 or higher
- **jq**: JSON processor for parsing API responses
- **curl**: HTTP client for API calls
- **Standard Linux utilities**: date, grep, awk, sed

### Authentication & Permissions
- Authenticated OpenShift session with cluster-admin or monitoring privileges
- SSH access to cluster nodes (for FIPS and NTP checks)
- Read permissions for cluster resources and configurations

### System Requirements
- Linux/Unix environment with bash shell
- Write permissions for output directory
- Network connectivity to OpenShift cluster

## Installation

1. **Download the script**:
   ```bash
   curl -O https://raw.githubusercontent.com/muneerkh/ocp-health-report/refs/heads/main/openshift-health-report.sh
   chmod +x openshift-health-report.sh
   ```

2. **Verify dependencies**:
   ```bash
   ./openshift-health-report.sh --test
   ```

3. **Authenticate with OpenShift**:
   ```bash
   oc login https://your-cluster-api:6443
   ```

## Usage

### Basic Usage
```bash
# Generate report with default settings
./openshift-health-report.sh

# Generate report with custom output file
./openshift-health-report.sh -o /path/to/cluster-health-report.html

# Generate report with debug output
./openshift-health-report.sh --debug
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output FILE` | Output HTML file path | `openshift-health-report-YYYYMMDD-HHMMSS.html` |
| `-l, --log-level LEVEL` | Set log level (ERROR, WARN, INFO, DEBUG) | `INFO` |
| `-t, --temp-dir DIR` | Temporary directory for processing | `/tmp/ocp-health-report-$$` |
| `--ssh-key FILE` | Specific SSH private key for node access | Auto-discover |
| `-v, --verbose` | Enable verbose output | Disabled |
| `-d, --debug` | Enable debug output | Disabled |
| `--test` | Run module tests (offline mode) | N/A |
| `-h, --help` | Show help message | N/A |
| `--version` | Show version information | N/A |

### Advanced Examples

```bash
# Generate report with custom temp directory and verbose output
./openshift-health-report.sh -t /custom/temp/dir --verbose

# Generate report with specific SSH key for node access
./openshift-health-report.sh --ssh-key ~/.ssh/cluster-key

# Generate report with debug logging to troubleshoot issues
./openshift-health-report.sh --debug -l DEBUG

# Generate report for specific cluster context
oc config use-context production-cluster
./openshift-health-report.sh -o production-health-$(date +%Y%m%d).html

# Run with comprehensive logging for troubleshooting
./openshift-health-report.sh --debug --verbose -l DEBUG -o debug-report.html
```

## Output

The script generates a comprehensive HTML report containing:

### Header Information
- Cluster name and version information
- OpenShift and Kubernetes versions with channel details
- Node count and report generation timestamp

### Health Sections
1. **FIPS Compliance Status**
   - Per-node FIPS mode verification with SSH validation
   - Compliance summary and security recommendations
   - Detailed node-by-node analysis with connectivity status

2. **NTP Synchronization**
   - Time synchronization status across all nodes
   - NTP server configuration and drift analysis
   - Chronyd service monitoring and time accuracy metrics

3. **etcd Encryption**
   - Encryption configuration status and validation
   - Key rotation monitoring and reencryption verification
   - Pod health verification and performance metrics

4. **IPSec Encryption**
   - OVN-Kubernetes IPSec configuration analysis
   - Pod-to-pod encryption status and mode detection
   - Network plugin compatibility and security validation

5. **Certificate Authority**
   - API server certificate validation and expiry tracking
   - Ingress certificate analysis and CA chain verification
   - Custom CA configuration and proxy certificate setup

6. **OAuth Authentication**
   - Identity provider configuration and type analysis
   - OAuth pod health and authentication flow validation
   - Multi-provider setup and integration status

7. **Cluster Operators**
   - All cluster operator health with degradation detection
   - Version information and update readiness status
   - Operator-specific recommendations and troubleshooting

8. **Update Service**
   - OpenShift update configuration and channel management
   - Available updates and upgrade path analysis
   - Connected vs airgapped update service configuration

9. **AlertManager Configuration**
   - Alert routing rules and notification channels
   - Receiver configuration and integration health
   - Alert history and silence management

10. **Loki Logging**
    - Log aggregation status and tenant configuration
    - Storage configuration and retention policies
    - Component health and query performance

11. **Cluster Connectivity**
    - Airgapped vs connected environment detection
    - Mirror registry configuration and image source policies
    - Network connectivity and external access validation

12. **Ingress Controller Analysis**
    - **Smart Placement Validation**: Actual vs. configured placement
    - **Node Selector Detection**: Supports multiple patterns (infra, infrastructure, worker)
    - **Toleration Analysis**: Taint handling for dedicated nodes
    - **Replica Recommendations**: HA optimization based on cluster topology
    - **Actionable Commands**: Ready-to-use oc patch commands

13. **Storage Classes**
    - Complete storage class inventory and CSI driver analysis
    - Backend storage types and provisioner configuration
    - Volume binding modes and reclaim policies
    - Default storage class validation and recommendations

14. **OpenShift Data Foundation (ODF)**
    - ODF operator installation and version tracking
    - Ceph cluster health and storage node status
    - NooBaa and Multi-Cloud Gateway (MCG) analysis
    - Storage capacity utilization and PV/PVC metrics
    - S3 endpoint configuration and bucket management

15. **Pod Network Details**
    - Network plugin configuration and CIDR analysis
    - Pod distribution across nodes and network health
    - MTU configuration and network performance metrics
    - Service network configuration and connectivity

16. **Node Details**
    - Complete node inventory with roles and labels
    - Machine Config Pool status and update progress
    - Node resource utilization and capacity planning
    - Taint and toleration analysis for workload placement

17. **Backup Status**
    - etcd backup verification and scheduling analysis
    - OADP operator status and backup job monitoring
    - Retention policies and recovery procedure validation
    - Backup failure analysis and recommendations

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Missing dependencies |
| 4 | Authentication error |

## Troubleshooting

### Common Issues

**Authentication Errors**
```bash
# Verify OpenShift login
oc whoami
oc auth can-i get nodes
```

**Missing Dependencies**
```bash
# Install required tools (RHEL/CentOS)
sudo yum install jq curl

# Install required tools (Ubuntu/Debian)
sudo apt-get install jq curl
```

**SSH Access Issues**
```bash
# Test SSH connectivity to nodes
oc get nodes -o wide
ssh core@<node-ip> "echo 'SSH working'"

# Debug SSH key discovery
ls -la ~/.ssh/
ssh-add -l
```

**Permission Errors**
```bash
# Check cluster permissions
oc auth can-i get clusteroperators
oc auth can-i get nodes
oc auth can-i get ingresscontrollers -n openshift-ingress-operator
```

**Ingress Placement Issues**
```bash
# Check ingress controller configuration
oc get ingresscontroller default -n openshift-ingress-operator -o yaml

# Verify ingress pod placement
oc get pods -n openshift-ingress -o wide

# Check node labels and taints
oc get nodes --show-labels
oc describe nodes | grep -A5 -B5 Taints
```

**FIPS Compliance Issues**
```bash
# Check FIPS status on nodes
oc debug node/<node-name> -- chroot /host cat /proc/sys/crypto/fips_enabled

# Verify Machine Config for FIPS
oc get machineconfig | grep fips
oc get machineconfig 99-master-fips -o yaml
```

**Storage and ODF Issues**
```bash
# Check ODF operator status
oc get csv -n openshift-storage | grep odf

# Verify Ceph cluster health
oc get cephcluster -n openshift-storage
oc get pods -n openshift-storage | grep -E "(ceph|noobaa|rook)"

# Check storage classes
oc get storageclass
oc describe storageclass <storage-class-name>
```

**Network and Connectivity Issues**
```bash
# Check network configuration
oc get network.config cluster -o yaml
oc get clusternetwork

# Verify pod network status
oc get pods --all-namespaces -o wide | grep -v Running
oc describe network.operator cluster
```

### Debug Mode

Enable debug mode for detailed troubleshooting:
```bash
./openshift-health-report.sh --debug -l DEBUG
```

This provides:
- Detailed command execution logs
- API response debugging
- SSH connection troubleshooting
- Temporary file locations

## Configuration

### SSH Key Discovery
The script automatically discovers SSH keys in `~/.ssh/` directory:
- Looks for common key names (id_rsa, id_ed25519, etc.)
- Tests connectivity with each discovered key
- Falls back to ssh-agent keys if available
- Supports custom key specification via `--ssh-key` option

### Ingress Placement Detection
The script intelligently detects various node placement patterns:
- **Direct NodeSelector**: `node-role.kubernetes.io/infra: ""`
- **Infrastructure Pattern**: `node-role.kubernetes.io/infrastructure: ""`
- **MatchLabels Structure**: `nodeSelector.matchLabels.node-role.kubernetes.io/infra`
- **NodeAffinity**: Complex affinity rules with matchLabels
- **Tolerations**: Taint handling for dedicated infrastructure nodes

### Temporary Files
- Creates secure temporary directory for processing
- Automatically cleans up on script completion
- Configurable location via `--temp-dir` option
- Proper file permissions (600) for security

## Enhanced Analysis Features

### Smart Placement Validation
The script provides intelligent ingress controller placement analysis that prioritizes **actual placement** over configuration:
- ✅ **Running on infra nodes**: Always shows "Fine" regardless of configuration
- ✅ **Mixed placement**: Shows "Fine" but warns about suboptimal distribution  
- ✅ **Worker placement**: Acceptable when no infra nodes are available
- ⚠️ **Configuration issues**: Only flagged when actual placement is problematic

### Comprehensive Security Analysis
- **FIPS Compliance**: Direct `/proc/sys/crypto/fips_enabled` validation with SSH connectivity testing
- **Encryption Status**: etcd encryption, IPSec pod-to-pod encryption, and certificate validation
- **Authentication**: OAuth identity provider analysis with multi-provider support
- **Certificate Management**: API and ingress certificate expiry tracking with CA chain validation

### Storage and Data Foundation Analysis
- **Multi-Storage Backend Support**: Analyzes various storage classes including Ceph, NFS, cloud providers
- **ODF Deep Dive**: Complete OpenShift Data Foundation health including Ceph cluster status
- **Capacity Planning**: Storage utilization metrics and growth trend analysis
- **Backup Validation**: Comprehensive backup status with OADP integration

### Network and Connectivity Analysis
- **Network Plugin Detection**: Supports OVN-Kubernetes, OpenShift SDN analysis
- **Connectivity Assessment**: Airgapped vs connected environment detection
- **Mirror Registry Analysis**: Image source policies and digest mirror sets
- **Pod Network Health**: CIDR allocation, MTU configuration, and distribution metrics

### Supported Node Selector Patterns
```yaml
# Standard infra node selector
nodeSelector:
  node-role.kubernetes.io/infra: ""

# Infrastructure node selector (alternative)
nodeSelector:
  node-role.kubernetes.io/infrastructure: ""

# Worker node selector
nodeSelector:
  node-role.kubernetes.io/worker: ""

# MatchLabels structure
nodeSelector:
  matchLabels:
    node-role.kubernetes.io/infra: ""

# NodeAffinity with matchLabels
nodeAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    nodeSelectorTerms:
    - matchLabels:
        node-role.kubernetes.io/infra: ""
```

### Actionable Recommendations
The report provides ready-to-use commands with proper styling:
```bash
# Configure ingress for infra nodes
oc patch ingresscontroller default -n openshift-ingress-operator \
  --type=merge -p '{"spec":{"nodePlacement":{"nodeSelector":{"node-role.kubernetes.io/infra":""}}}}'

# Scale replicas for HA
oc patch ingresscontroller default -n openshift-ingress-operator \
  --type=merge -p '{"spec":{"replicas":3}}'

# Enable etcd encryption
oc patch apiserver cluster --type=merge \
  -p '{"spec":{"encryption":{"type":"aescbc"}}}'

# Configure FIPS mode
oc patch machineconfig 99-master-fips --type=merge \
  -p '{"spec":{"fips":true}}'
```

## Data Collection Details

### Comprehensive Health Metrics
The script collects over **200+ data points** across all cluster components:

**Security Metrics**: FIPS status per node, encryption configurations, certificate expiry dates, OAuth provider details
**Performance Metrics**: Pod counts, resource utilization, storage capacity, network MTU settings
**Configuration Metrics**: Node selectors, tolerations, storage classes, backup schedules
**Operational Metrics**: Operator health, update channels, alert configurations, log retention

### Intelligent Error Handling
- **Retry Logic**: Automatic retry for transient API failures with exponential backoff
- **Graceful Degradation**: Continues collection even if individual modules fail
- **Detailed Logging**: Comprehensive debug output for troubleshooting
- **Validation**: JSON parsing validation and data integrity checks

### SSH-Based Node Validation
- **Automatic Key Discovery**: Finds SSH keys in `~/.ssh/` directory automatically
- **Multi-Key Testing**: Tests multiple keys until successful connection
- **Secure Access**: Uses proper SSH permissions and connection handling
- **Fallback Support**: Graceful handling when SSH access is unavailable

## Security Considerations

- Script requires cluster-admin privileges for comprehensive checks
- SSH keys are handled securely with proper permissions (600)
- Temporary files are created with restricted access in isolated directories
- No sensitive data is logged in normal operation mode
- HTML output contains no embedded credentials or secrets
- All API calls use authenticated OpenShift CLI sessions
- Ingress analysis respects cluster security policies and RBAC

## Contributing

### Development Setup
```bash
# Clone repository
git clone https://github.com/muneerkh/ocp-health-report.git
cd ocp-health-report

# Run tests
./openshift-health-report.sh --test

# Enable debug mode for development
export DEBUG=true
```

### Code Style
- Follow bash best practices with `set -euo pipefail`
- Use proper error handling and logging
- Include comprehensive function documentation
- Use consistent variable naming conventions
- Test all new features with mock data
- Validate HTML output and CSS styling

### Testing Guidelines
- Create test scripts for new features
- Verify JSON parsing with various input formats
- Test edge cases and error conditions
- Validate HTML rendering and CSS compatibility
- Ensure proper cleanup of temporary files

## License

MIT License - see script header for full license text.

## Author

**Muneer Hussain**  
Email: muneerkh@gmail.com

## Version History

- **v1.0.0**: Initial release with comprehensive health checking capabilities including:
  - FIPS compliance validation across all nodes
  - NTP synchronization monitoring with chronyd service checks
  - etcd encryption status and key rotation analysis
  - IPSec encryption configuration for OVN-Kubernetes
  - Certificate authority validation for API and ingress
  - OAuth authentication provider analysis
  - Complete cluster operator health monitoring
  - Update service configuration and channel management
  - AlertManager routing and receiver configuration
  - Loki logging tenant setup and component health
  - Cluster connectivity detection (airgapped vs connected)
  - Advanced ingress controller placement analysis
  - Storage classes and CSI driver inventory
  - OpenShift Data Foundation (ODF) comprehensive health check
  - Pod network details and configuration analysis
  - Detailed node inventory with Machine Config Pool status
  - Backup status verification with OADP integration
  - Professional HTML report generation with responsive design
  - Actionable recommendations with copy-ready commands

---

For issues, feature requests, or contributions, please contact the author or submit issues through the appropriate channels.