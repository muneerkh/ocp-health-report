# OpenShift Cluster Health Report Generator

A comprehensive bash script that generates detailed HTML health reports for OpenShift clusters, providing insights into cluster status, security compliance, and operational health with intelligent placement validation and actionable recommendations.

## Features

### Core Health Checks
- **FIPS Compliance**: Validates FIPS mode across all cluster nodes with SSH connectivity
- **NTP Synchronization**: Checks time synchronization status on all nodes
- **etcd Encryption**: Monitors etcd encryption configuration and key rotation status
- **Ingress Controller**: Advanced placement validation with infra node preference
- **Cluster Status**: Overall cluster health, version information, and channel details
- **Node Health**: Individual node status and resource utilization
- **Operator Status**: Health of cluster operators with degradation detection
- **AlertManager Configuration**: Alert routing and notification setup
- **Loki Logging**: Log aggregation and storage status
- **Backup Status**: etcd backup and cronjob monitoring

### Advanced Ingress Analysis
- **Smart Placement Detection**: Prioritizes actual pod placement over configuration
- **Multiple Node Selector Patterns**: Supports infra, infrastructure, worker, and matchLabels
- **Toleration Analysis**: Detects taint tolerations for proper node scheduling
- **NodeAffinity Support**: Handles complex node affinity configurations
- **Replica Optimization**: Intelligent HA recommendations based on cluster size

### Report Features
- **Professional HTML Output**: Modern, responsive design with gradient styling
- **Real-time Status Indicators**: Color-coded status badges for quick assessment
- **Actionable Commands**: Copy-ready oc patch commands with proper styling
- **Detailed Metrics**: Comprehensive data collection with error handling
- **Timestamp Tracking**: Report generation time and data collection timestamps
- **Export Capabilities**: Self-contained HTML reports for sharing

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
   - Detailed node-by-node analysis

2. **NTP Synchronization**
   - Time synchronization status across all nodes
   - NTP server configuration and drift analysis
   - Chronyd service monitoring

3. **etcd Encryption**
   - Encryption configuration status and validation
   - Key rotation monitoring and history
   - Pod health verification and performance metrics

4. **Ingress Controller Analysis**
   - **Smart Placement Validation**: Actual vs. configured placement
   - **Node Selector Detection**: Supports multiple patterns (infra, infrastructure, worker)
   - **Toleration Analysis**: Taint handling for dedicated nodes
   - **Replica Recommendations**: HA optimization based on cluster topology
   - **Actionable Commands**: Ready-to-use oc patch commands

5. **Cluster Overview**
   - Overall cluster health and API availability
   - Control plane component status
   - Version compatibility matrix

6. **Node Status**
   - Individual node health and conditions
   - Resource utilization and capacity planning
   - Taints and labels analysis

7. **Operator Health**
   - Cluster operator status with degradation details
   - Version information and update readiness
   - Operator-specific recommendations

8. **AlertManager Configuration**
   - Alert routing rules and notification channels
   - Silence status and alert history
   - Integration health checks

9. **Loki Logging**
   - Log aggregation status and performance
   - Storage configuration and retention
   - Query performance and indexing

10. **Backup Status**
    - etcd backup verification and scheduling
    - Cronjob monitoring and success rates
    - Retention policies and recovery procedures

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

## Enhanced Ingress Controller Analysis

### Smart Placement Validation
The script provides intelligent ingress controller placement analysis that prioritizes **actual placement** over configuration:
- ✅ **Running on infra nodes**: Always shows "Fine" regardless of configuration
- ✅ **Mixed placement**: Shows "Fine" but warns about suboptimal distribution  
- ✅ **Worker placement**: Acceptable when no infra nodes are available
- ⚠️ **Configuration issues**: Only flagged when actual placement is problematic

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
# Configure for infra nodes
oc patch ingresscontroller default -n openshift-ingress-operator \
  --type=merge -p '{"spec":{"nodePlacement":{"nodeSelector":{"node-role.kubernetes.io/infra":""}}}}'

# Scale replicas for HA
oc patch ingresscontroller default -n openshift-ingress-operator \
  --type=merge -p '{"spec":{"replicas":3}}'
```

## Security Considerations

- Script requires cluster-admin privileges for comprehensive checks
- SSH keys are handled securely with proper permissions
- Temporary files are created with restricted access (600)
- No sensitive data is logged in normal operation
- HTML output contains no embedded credentials
- Ingress analysis respects cluster security policies

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

- **v1.0.0**: Initial release with comprehensive health checking capabilities
- **v1.1.0**: Added advanced ingress controller analysis with smart placement detection
- **v1.2.0**: Enhanced node selector pattern support (infra, infrastructure, matchLabels)
- **v1.3.0**: Improved placement validation prioritizing actual over configured placement
- **v1.4.0**: Added actionable recommendations with styled code blocks and oc commands

---

For issues, feature requests, or contributions, please contact the author or submit issues through the appropriate channels.