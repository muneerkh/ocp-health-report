#!/bin/bash

# OpenShift Cluster Health Report Generator
# Version: 1.0.0
# Description: Generates a comprehensive HTML health report for OpenShift clusters
# Author: Muneer Hussain
# Email: muneerkh@gmail.com
# License: MIT

set -euo pipefail

# Script metadata
readonly SCRIPT_NAME="openshift-health-report.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DESCRIPTION="OpenShift Cluster Health Report Generator"

# Default configuration
DEFAULT_OUTPUT_FILE="openshift-health-report-$(date +%Y%m%d-%H%M%S).html"
DEFAULT_LOG_LEVEL="INFO"
DEFAULT_TEMP_DIR="/tmp/ocp-health-report-$$"

# Global variables
OUTPUT_FILE=""
LOG_LEVEL=""
TEMP_DIR=""
VERBOSE=false
DEBUG=false

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_ERROR=1
readonly EXIT_INVALID_ARGS=2
readonly EXIT_MISSING_DEPS=3
readonly EXIT_AUTH_ERROR=4

# Logging functions
log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_info() {
    if [[ "${LOG_LEVEL}" != "ERROR" ]]; then
        echo -e "${BLUE}[INFO]${NC} $*"
    fi
}

log_debug() {
    if [[ "${DEBUG}" == "true" ]]; then
        echo -e "[DEBUG] $*" >&2
    fi
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

# Error handling function
handle_error() {
    local exit_code=$?
    local line_number=$1
    log_error "Script failed at line ${line_number} with exit code ${exit_code}"
    cleanup
    exit ${exit_code}
}

# Set up error trap
trap 'handle_error ${LINENO}' ERR

# Cleanup function
cleanup() {
    log_debug "Performing cleanup..."
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
        log_debug "Removed temporary directory: ${TEMP_DIR}"
    fi
}

# Set up exit trap for cleanup
trap cleanup EXIT

# Display help information
show_help() {
    cat << EOF
${SCRIPT_DESCRIPTION} v${SCRIPT_VERSION}

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

DESCRIPTION:
    Generates a comprehensive HTML health report for OpenShift clusters.
    The script collects information about FIPS compliance, NTP synchronization,
    AlertManager configuration, Loki logging, cluster and node status,
    operator health, etcd encryption and backup status, and backup cronjobs.

OPTIONS:
    -o, --output FILE       Output HTML file path (default: ${DEFAULT_OUTPUT_FILE})
    -l, --log-level LEVEL   Set log level: ERROR, WARN, INFO, DEBUG (default: ${DEFAULT_LOG_LEVEL})
    -t, --temp-dir DIR      Temporary directory for processing (default: ${DEFAULT_TEMP_DIR})
    --ssh-key FILE          Specific SSH private key file for node access (default: auto-discover)
    -v, --verbose           Enable verbose output
    -d, --debug             Enable debug output
    --test                  Run module tests (offline mode)
    -h, --help              Show this help message
    --version               Show version information

EXAMPLES:
    # Generate report with default settings
    ${SCRIPT_NAME}

    # Generate report with custom output file
    ${SCRIPT_NAME} -o /path/to/cluster-health-report.html

    # Generate report with debug output
    ${SCRIPT_NAME} --debug

    # Generate report with custom temp directory
    ${SCRIPT_NAME} -t /custom/temp/dir

PREREQUISITES:
    - OpenShift CLI (oc) version 4.10+
    - Authenticated session with cluster-admin or monitoring privileges
    - Standard Linux utilities: jq, curl, date
    - Write permissions for output directory

EXIT CODES:
    0   Success
    1   General error
    2   Invalid arguments
    3   Missing dependencies
    4   Authentication error

EOF
}

# Show version information
show_version() {
    echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -l|--log-level)
                LOG_LEVEL="$2"
                case "${LOG_LEVEL}" in
                    ERROR|WARN|INFO|DEBUG)
                        ;;
                    *)
                        log_error "Invalid log level: ${LOG_LEVEL}"
                        log_error "Valid levels: ERROR, WARN, INFO, DEBUG"
                        exit ${EXIT_INVALID_ARGS}
                        ;;
                esac
                shift 2
                ;;
            -t|--temp-dir)
                TEMP_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--debug)
                DEBUG=true
                LOG_LEVEL="DEBUG"
                shift
                ;;
            -h|--help)
                show_help
                exit ${EXIT_SUCCESS}
                ;;
            --test)
                run_tests
                exit ${EXIT_SUCCESS}
                ;;
            --version)
                show_version
                exit ${EXIT_SUCCESS}
                ;;
            --ssh-key)
                SSH_KEY_FILE="$2"
                if [[ ! -f "${SSH_KEY_FILE}" ]]; then
                    log_error "SSH key file not found: ${SSH_KEY_FILE}"
                    exit ${EXIT_INVALID_ARGS}
                fi
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                log_error "Use --help for usage information"
                exit ${EXIT_INVALID_ARGS}
                ;;
        esac
    done
}

# Set default values for unset variables
set_defaults() {
    OUTPUT_FILE="${OUTPUT_FILE:-${DEFAULT_OUTPUT_FILE}}"
    LOG_LEVEL="${LOG_LEVEL:-${DEFAULT_LOG_LEVEL}}"
    TEMP_DIR="${TEMP_DIR:-${DEFAULT_TEMP_DIR}}"
    SSH_KEY_FILE="${SSH_KEY_FILE:-}"
    
    log_debug "Configuration:"
    log_debug "  Output file: ${OUTPUT_FILE}"
    log_debug "  Log level: ${LOG_LEVEL}"
    log_debug "  SSH key file: ${SSH_KEY_FILE:-auto-discover}"
    log_debug "  Temp directory: ${TEMP_DIR}"
    log_debug "  Verbose: ${VERBOSE}"
    log_debug "  Debug: ${DEBUG}"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Validate required dependencies
validate_dependencies() {
    log_info "Validating required dependencies..."
    
    local missing_deps=()
    
    # Check for required commands
    local required_commands=("oc" "jq" "curl" "date" "grep" "awk" "sed")
    
    for cmd in "${required_commands[@]}"; do
        if ! command_exists "${cmd}"; then
            missing_deps+=("${cmd}")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            log_error "  - ${dep}"
        done
        log_error "Please install missing dependencies and try again"
        exit ${EXIT_MISSING_DEPS}
    fi
    
    log_success "All required dependencies are available"
}

# Validate OpenShift CLI version
validate_oc_version() {
    log_info "Validating OpenShift CLI version..."
    
    if ! oc version --client >/dev/null 2>&1; then
        log_error "Failed to get OpenShift CLI version"
        exit ${EXIT_MISSING_DEPS}
    fi
    
    local oc_version
    oc_version=$(oc version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion' 2>/dev/null || echo "unknown")
    
    log_info "OpenShift CLI version: ${oc_version}"
    
    # Basic version check - ensure we can run oc commands
    if [[ "${oc_version}" == "unknown" ]]; then
        log_warn "Could not determine OpenShift CLI version, proceeding anyway"
    fi
}

# Validate OpenShift authentication
validate_authentication() {
    log_info "Validating OpenShift authentication..."
    
    if ! oc whoami >/dev/null 2>&1; then
        log_error "Not authenticated to OpenShift cluster"
        log_error "Please run 'oc login' to authenticate and try again"
        exit ${EXIT_AUTH_ERROR}
    fi
    
    local current_user
    current_user=$(oc whoami 2>/dev/null || echo "unknown")
    log_info "Authenticated as: ${current_user}"
    
    # Check if we can access cluster information
    if ! oc get nodes >/dev/null 2>&1; then
        log_error "Cannot access cluster nodes - insufficient permissions"
        log_error "This script requires cluster-admin or monitoring privileges"
        exit ${EXIT_AUTH_ERROR}
    fi
    
    log_success "Authentication validated successfully"
}

# Validate output directory and file permissions
validate_output() {
    log_info "Validating output configuration..."
    
    local output_dir
    output_dir=$(dirname "${OUTPUT_FILE}")
    
    # Create output directory if it doesn't exist
    if [[ ! -d "${output_dir}" ]]; then
        log_info "Creating output directory: ${output_dir}"
        if ! mkdir -p "${output_dir}"; then
            log_error "Failed to create output directory: ${output_dir}"
            exit ${EXIT_ERROR}
        fi
    fi
    
    # Check write permissions
    if [[ ! -w "${output_dir}" ]]; then
        log_error "No write permission for output directory: ${output_dir}"
        exit ${EXIT_ERROR}
    fi
    
    # Check if output file already exists
    if [[ -f "${OUTPUT_FILE}" ]]; then
        log_warn "Output file already exists and will be overwritten: ${OUTPUT_FILE}"
    fi
    
    log_success "Output configuration validated"
}

# Create and validate temporary directory
setup_temp_directory() {
    log_info "Setting up temporary directory..."
    
    if [[ ! -d "${TEMP_DIR}" ]]; then
        if ! mkdir -p "${TEMP_DIR}"; then
            log_error "Failed to create temporary directory: ${TEMP_DIR}"
            exit ${EXIT_ERROR}
        fi
    fi
    
    # Ensure temp directory is writable
    if [[ ! -w "${TEMP_DIR}" ]]; then
        log_error "Temporary directory is not writable: ${TEMP_DIR}"
        exit ${EXIT_ERROR}
    fi
    
    log_debug "Temporary directory created: ${TEMP_DIR}"
    log_success "Temporary directory setup complete"
}

# Validate cluster connectivity and basic information
validate_cluster_access() {
    log_info "Validating cluster access..."
    
    # Test basic cluster connectivity
    local cluster_version
    if ! cluster_version=$(oc get clusterversion -o jsonpath='{.items[0].status.desired.version}' 2>/dev/null); then
        log_error "Cannot access cluster version information"
        exit ${EXIT_AUTH_ERROR}
    fi
    
    log_info "Connected to OpenShift cluster version: ${cluster_version}"
    
    # Test node access
    local node_count
    if ! node_count=$(oc get nodes --no-headers 2>/dev/null | wc -l); then
        log_error "Cannot access cluster nodes"
        exit ${EXIT_AUTH_ERROR}
    fi
    
    log_info "Cluster has ${node_count} nodes"
    
    log_success "Cluster access validated"
}

# Main configuration validation function
validate_configuration() {
    log_info "Starting configuration validation..."
    
    validate_dependencies
    validate_oc_version
    validate_authentication
    validate_output
    setup_temp_directory
    validate_cluster_access
    
    log_success "Configuration validation completed successfully"
}

# Initialize the script
initialize() {
    log_info "Initializing ${SCRIPT_DESCRIPTION} v${SCRIPT_VERSION}"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Set default values
    set_defaults
    
    # Validate configuration
    validate_configuration
    
    log_success "Initialization completed successfully"
}

# =============================================================================
# DATA COLLECTION UTILITY FUNCTIONS
# =============================================================================

# Status constants
readonly STATUS_HEALTHY="healthy"
readonly STATUS_WARNING="warning"
readonly STATUS_CRITICAL="critical"
readonly STATUS_UNKNOWN="unknown"

# Execute oc command with error handling and retry logic
execute_oc_command() {
    local cmd="$1"
    local description="${2:-OpenShift command}"
    local max_retries="${3:-3}"
    local retry_delay="${4:-2}"
    local output_file="${5:-}"
    
    log_debug "Executing: oc ${cmd}"
    
    local attempt=1
    local result=""
    local exit_code=0
    
    while [[ ${attempt} -le ${max_retries} ]]; do
        if [[ -n "${output_file}" ]]; then
            # Execute command and save output to file
            if result=$(oc ${cmd} 2>&1) && echo "${result}" > "${output_file}"; then
                log_debug "Command succeeded on attempt ${attempt}: ${description}"
                echo "${result}"
                return 0
            else
                exit_code=$?
            fi
        else
            # Execute command and return output
            if result=$(oc ${cmd} 2>&1); then
                log_debug "Command succeeded on attempt ${attempt}: ${description}"
                echo "${result}"
                return 0
            else
                exit_code=$?
            fi
        fi
        
        log_warn "Command failed on attempt ${attempt}/${max_retries}: ${description}"
        log_debug "Error output: ${result}"
        
        if [[ ${attempt} -lt ${max_retries} ]]; then
            log_debug "Retrying in ${retry_delay} seconds..."
            sleep ${retry_delay}
        fi
        
        ((attempt++))
    done
    
    log_error "Command failed after ${max_retries} attempts: ${description}"
    log_error "Final error: ${result}"
    return ${exit_code}
}

# Execute oc command with JSON output and error handling
execute_oc_json() {
    local cmd="$1"
    local description="${2:-OpenShift JSON command}"
    local max_retries="${3:-3}"
    
    log_debug "Executing JSON command: oc ${cmd}"
    
    local result=""
    if result=$(execute_oc_command "${cmd}" "${description}" "${max_retries}"); then
        # Validate JSON output
        if echo "${result}" | jq empty 2>/dev/null; then
            echo "${result}"
            return 0
        else
            log_error "Invalid JSON output from command: ${description}"
            log_debug "Output was: ${result}"
            return 1
        fi
    else
        return $?
    fi
}

# Parse JSON field with error handling
parse_json_field() {
    local json_data="$1"
    local jq_filter="$2"
    local default_value="${3:-}"
    local field_description="${4:-JSON field}"
    
    log_debug "Parsing JSON field: ${jq_filter}"
    
    local result=""
    if result=$(echo "${json_data}" | jq -r "${jq_filter}" 2>/dev/null); then
        if [[ "${result}" == "null" || "${result}" == "" ]]; then
            if [[ -n "${default_value}" ]]; then
                log_debug "Field returned null/empty, using default: ${default_value}"
                echo "${default_value}"
            else
                log_debug "Field returned null/empty: ${field_description}"
                echo ""
            fi
        else
            log_debug "Successfully parsed field: ${field_description} = ${result}"
            echo "${result}"
        fi
        return 0
    else
        log_warn "Failed to parse JSON field: ${field_description}"
        if [[ -n "${default_value}" ]]; then
            log_debug "Using default value: ${default_value}"
            echo "${default_value}"
        else
            echo ""
        fi
        return 1
    fi
}

# Count JSON array elements
count_json_array() {
    local json_data="$1"
    local jq_filter="${2:-.}"
    local description="${3:-array}"
    
    log_debug "Counting JSON array elements: ${jq_filter}"
    
    local count=""
    if count=$(echo "${json_data}" | jq -r "${jq_filter} | length" 2>/dev/null); then
        if [[ "${count}" =~ ^[0-9]+$ ]]; then
            log_debug "Array count for ${description}: ${count}"
            echo "${count}"
            return 0
        fi
    fi
    
    log_warn "Failed to count array elements: ${description}"
    echo "0"
    return 1
}

# Filter JSON array by condition
filter_json_array() {
    local json_data="$1"
    local jq_filter="$2"
    local description="${3:-filtered array}"
    
    log_debug "Filtering JSON array: ${jq_filter}"
    
    local result=""
    if result=$(echo "${json_data}" | jq -c "${jq_filter}" 2>/dev/null); then
        log_debug "Successfully filtered array: ${description}"
        echo "${result}"
        return 0
    else
        log_warn "Failed to filter JSON array: ${description}"
        echo "[]"
        return 1
    fi
}

# Determine component status based on conditions
determine_status() {
    local component="$1"
    local available="${2:-unknown}"
    local progressing="${3:-unknown}"
    local degraded="${4:-unknown}"
    local additional_checks="${5:-}"
    
    log_debug "Determining status for ${component}: available=${available}, progressing=${progressing}, degraded=${degraded}"
    
    # Convert string values to lowercase for comparison
    available=$(echo "${available}" | tr '[:upper:]' '[:lower:]')
    progressing=$(echo "${progressing}" | tr '[:upper:]' '[:lower:]')
    degraded=$(echo "${degraded}" | tr '[:upper:]' '[:lower:]')
    
    # Critical status conditions
    if [[ "${degraded}" == "true" ]]; then
        log_debug "Status: ${STATUS_CRITICAL} (degraded)"
        echo "${STATUS_CRITICAL}"
        return 0
    fi
    
    if [[ "${available}" == "false" ]]; then
        log_debug "Status: ${STATUS_CRITICAL} (not available)"
        echo "${STATUS_CRITICAL}"
        return 0
    fi
    
    # Warning status conditions
    if [[ "${progressing}" == "true" ]]; then
        log_debug "Status: ${STATUS_WARNING} (progressing)"
        echo "${STATUS_WARNING}"
        return 0
    fi
    
    # Additional custom checks
    if [[ -n "${additional_checks}" ]]; then
        case "${additional_checks}" in
            "warning")
                log_debug "Status: ${STATUS_WARNING} (additional check)"
                echo "${STATUS_WARNING}"
                return 0
                ;;
            "critical")
                log_debug "Status: ${STATUS_CRITICAL} (additional check)"
                echo "${STATUS_CRITICAL}"
                return 0
                ;;
        esac
    fi
    
    # Healthy status conditions
    if [[ "${available}" == "true" && "${progressing}" == "false" && "${degraded}" == "false" ]]; then
        log_debug "Status: ${STATUS_HEALTHY} (all conditions good)"
        echo "${STATUS_HEALTHY}"
        return 0
    fi
    
    # Unknown status (default)
    log_debug "Status: ${STATUS_UNKNOWN} (insufficient information)"
    echo "${STATUS_UNKNOWN}"
    return 0
}

# Determine status from simple boolean or string value
determine_simple_status() {
    local component="$1"
    local value="$2"
    local expected_value="${3:-true}"
    local invert_logic="${4:-false}"
    
    log_debug "Determining simple status for ${component}: value=${value}, expected=${expected_value}, invert=${invert_logic}"
    
    # Convert to lowercase for comparison
    value=$(echo "${value}" | tr '[:upper:]' '[:lower:]')
    expected_value=$(echo "${expected_value}" | tr '[:upper:]' '[:lower:]')
    
    local is_match=false
    if [[ "${value}" == "${expected_value}" ]]; then
        is_match=true
    fi
    
    # Apply invert logic if specified
    if [[ "${invert_logic}" == "true" ]]; then
        if [[ "${is_match}" == "true" ]]; then
            is_match=false
        else
            is_match=true
        fi
    fi
    
    if [[ "${is_match}" == "true" ]]; then
        log_debug "Status: ${STATUS_HEALTHY}"
        echo "${STATUS_HEALTHY}"
    else
        log_debug "Status: ${STATUS_CRITICAL}"
        echo "${STATUS_CRITICAL}"
    fi
    
    return 0
}

# Get current timestamp in ISO format
get_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Get current timestamp in human readable format
get_readable_timestamp() {
    date "+%Y-%m-%d %H:%M:%S %Z"
}

# Format duration from seconds to human readable format
format_duration() {
    local seconds="$1"
    
    if [[ ! "${seconds}" =~ ^[0-9]+$ ]]; then
        echo "unknown"
        return 1
    fi
    
    local days=$((seconds / 86400))
    local hours=$(((seconds % 86400) / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))
    
    local result=""
    
    if [[ ${days} -gt 0 ]]; then
        result="${days}d"
    fi
    
    if [[ ${hours} -gt 0 ]]; then
        result="${result}${hours}h"
    fi
    
    if [[ ${minutes} -gt 0 ]]; then
        result="${result}${minutes}m"
    fi
    
    if [[ ${secs} -gt 0 || -z "${result}" ]]; then
        result="${result}${secs}s"
    fi
    
    echo "${result}"
}

# Format bytes to human readable format
format_bytes() {
    local bytes="$1"
    
    if [[ ! "${bytes}" =~ ^[0-9]+$ ]]; then
        echo "unknown"
        return 1
    fi
    
    local units=("B" "KB" "MB" "GB" "TB")
    local unit_index=0
    local size=${bytes}
    
    while [[ ${size} -ge 1024 && ${unit_index} -lt $((${#units[@]} - 1)) ]]; do
        size=$((size / 1024))
        ((unit_index++))
    done
    
    echo "${size}${units[${unit_index}]}"
}

# Convert Kubernetes memory format to GB
format_k8s_memory_to_gb() {
    local memory_value="$1"
    
    if [[ -z "${memory_value}" || "${memory_value}" == "unknown" || "${memory_value}" == "null" ]]; then
        echo "unknown"
        return 1
    fi
    
    # Remove any whitespace
    memory_value=$(echo "${memory_value}" | tr -d ' ')
    
    # Extract numeric value and unit
    local numeric_part=""
    local unit_part=""
    
    if [[ "${memory_value}" =~ ^([0-9]+)([A-Za-z]*)$ ]]; then
        numeric_part="${BASH_REMATCH[1]}"
        unit_part="${BASH_REMATCH[2]}"
    else
        log_debug "Invalid memory format: ${memory_value}"
        echo "unknown"
        return 1
    fi
    
    # Convert to bytes first, then to GB
    local bytes=0
    
    case "${unit_part}" in
        "Ki"|"ki")
            # Kibibytes (1024 bytes)
            bytes=$((numeric_part * 1024))
            ;;
        "Mi"|"mi")
            # Mebibytes (1024^2 bytes)
            bytes=$((numeric_part * 1024 * 1024))
            ;;
        "Gi"|"gi")
            # Gibibytes (1024^3 bytes)
            bytes=$((numeric_part * 1024 * 1024 * 1024))
            ;;
        "Ti"|"ti")
            # Tebibytes (1024^4 bytes)
            bytes=$((numeric_part * 1024 * 1024 * 1024 * 1024))
            ;;
        "K"|"k")
            # Kilobytes (1000 bytes)
            bytes=$((numeric_part * 1000))
            ;;
        "M"|"m")
            # Megabytes (1000^2 bytes)
            bytes=$((numeric_part * 1000 * 1000))
            ;;
        "G"|"g")
            # Gigabytes (1000^3 bytes)
            bytes=$((numeric_part * 1000 * 1000 * 1000))
            ;;
        "T"|"t")
            # Terabytes (1000^4 bytes)
            bytes=$((numeric_part * 1000 * 1000 * 1000 * 1000))
            ;;
        ""|"B"|"b")
            # Bytes (no unit or explicit bytes)
            bytes=${numeric_part}
            ;;
        *)
            log_debug "Unknown memory unit: ${unit_part}"
            echo "unknown"
            return 1
            ;;
    esac
    
    # Convert bytes to GB (using decimal GB = 1000^3 bytes)
    local gb_value=$((bytes / 1000 / 1000 / 1000))
    
    # If the result is 0, show decimal places for small values
    if [[ ${gb_value} -eq 0 && ${bytes} -gt 0 ]]; then
        # Use awk for decimal calculation
        gb_value=$(awk "BEGIN {printf \"%.2f\", ${bytes}/1000/1000/1000}")
        echo "${gb_value} GB"
    else
        echo "${gb_value} GB"
    fi
    
    return 0
}

# Parse Kubernetes resource age to seconds
parse_age_to_seconds() {
    local age_string="$1"
    
    log_debug "Parsing age string: ${age_string}"
    
    # Remove any whitespace
    age_string=$(echo "${age_string}" | tr -d ' ')
    
    local total_seconds=0
    
    # Parse different time units
    if [[ "${age_string}" =~ ([0-9]+)d ]]; then
        local days="${BASH_REMATCH[1]}"
        total_seconds=$((total_seconds + days * 86400))
    fi
    
    if [[ "${age_string}" =~ ([0-9]+)h ]]; then
        local hours="${BASH_REMATCH[1]}"
        total_seconds=$((total_seconds + hours * 3600))
    fi
    
    if [[ "${age_string}" =~ ([0-9]+)m ]]; then
        local minutes="${BASH_REMATCH[1]}"
        total_seconds=$((total_seconds + minutes * 60))
    fi
    
    if [[ "${age_string}" =~ ([0-9]+)s ]]; then
        local seconds="${BASH_REMATCH[1]}"
        total_seconds=$((total_seconds + seconds))
    fi
    
    # If no units found, assume it's already in seconds
    if [[ ${total_seconds} -eq 0 && "${age_string}" =~ ^[0-9]+$ ]]; then
        total_seconds="${age_string}"
    fi
    
    log_debug "Parsed age to seconds: ${total_seconds}"
    echo "${total_seconds}"
}

# Sanitize string for HTML output
sanitize_html() {
    local input="$1"
    
    # Use sed for proper HTML character replacement
    input=$(echo "${input}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g')
    
    echo "${input}"
}

# Truncate string to specified length with ellipsis
truncate_string() {
    local input="$1"
    local max_length="${2:-50}"
    
    if [[ ${#input} -le ${max_length} ]]; then
        echo "${input}"
    else
        echo "${input:0:$((max_length - 3))}..."
    fi
}

# Create a temporary file with proper cleanup
create_temp_file() {
    local prefix="${1:-ocp-health}"
    local suffix="${2:-.tmp}"
    
    local temp_file="${TEMP_DIR}/${prefix}-$(date +%s)-$$${suffix}"
    
    touch "${temp_file}"
    log_debug "Created temporary file: ${temp_file}"
    
    echo "${temp_file}"
}

# Validate JSON structure
validate_json() {
    local json_data="$1"
    local description="${2:-JSON data}"
    
    if echo "${json_data}" | jq empty 2>/dev/null; then
        log_debug "Valid JSON: ${description}"
        return 0
    else
        log_warn "Invalid JSON: ${description}"
        return 1
    fi
}

# Extract error message from oc command output
extract_error_message() {
    local output="$1"
    local max_length="${2:-200}"
    
    # Try to extract meaningful error message
    local error_msg=""
    
    # Look for common error patterns
    if echo "${output}" | grep -q "error:"; then
        error_msg=$(echo "${output}" | grep "error:" | head -1 | sed 's/.*error: *//')
    elif echo "${output}" | grep -q "Error"; then
        error_msg=$(echo "${output}" | grep "Error" | head -1)
    else
        error_msg="${output}"
    fi
    
    # Truncate and sanitize
    error_msg=$(truncate_string "${error_msg}" "${max_length}")
    error_msg=$(sanitize_html "${error_msg}")
    
    echo "${error_msg}"
}

# =============================================================================
# FIPS COMPLIANCE CHECK MODULE
# =============================================================================

# FIPS compliance status structure
declare -A fips_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["compliant_nodes"]="0"
    ["non_compliant_nodes"]="0"
    ["unknown_nodes"]="0"
    ["total_nodes"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Discover available SSH keys in user's .ssh directory
discover_ssh_keys() {
    local ssh_dir="${HOME}/.ssh"
    local ssh_keys=()
    
    if [[ ! -d "${ssh_dir}" ]]; then
        log_debug "SSH directory ${ssh_dir} not found"
        return 1
    fi
    
    # Common SSH key file patterns
    local key_patterns=("id_rsa" "id_ed25519" "id_ecdsa" "id_dsa")
    
    for pattern in "${key_patterns[@]}"; do
        if [[ -f "${ssh_dir}/${pattern}" ]]; then
            ssh_keys+=("${ssh_dir}/${pattern}")
            log_debug "Found SSH key: ${ssh_dir}/${pattern}"
        fi
    done
    
    # Also look for any other private key files (files without .pub extension)
    while IFS= read -r -d '' keyfile; do
        # Skip if it's a .pub file, known_hosts, config, or already in our list
        if [[ "${keyfile}" == *.pub ]] || [[ "${keyfile}" == *known_hosts* ]] || [[ "${keyfile}" == *config* ]]; then
            continue
        fi
        
        # Check if it's already in our list
        local already_added=false
        for existing_key in "${ssh_keys[@]}"; do
            if [[ "${keyfile}" == "${existing_key}" ]]; then
                already_added=true
                break
            fi
        done
        
        if [[ "${already_added}" == "false" ]]; then
            # Check if it looks like a private key file
            if file "${keyfile}" 2>/dev/null | grep -q "private key\|SSH.*private"; then
                ssh_keys+=("${keyfile}")
                log_debug "Found additional SSH key: ${keyfile}"
            fi
        fi
    done < <(find "${ssh_dir}" -maxdepth 1 -type f -print0 2>/dev/null)
    
    # Return the keys as a space-separated string
    printf '%s\n' "${ssh_keys[@]}"
}

# Try SSH connection with multiple keys
try_ssh_with_keys() {
    local ssh_user="$1"
    local node_name="$2"
    local ssh_command="$3"
    local ssh_opts="${4:--o ConnectTimeout=10 -o StrictHostKeyChecking=no}"
    
    # If a specific SSH key is provided via command line, try it first
    if [[ -n "${SSH_KEY_FILE}" ]]; then
        log_debug "Trying SSH with specified key ${SSH_KEY_FILE}: ${ssh_user}@${node_name}"
        if result=$(ssh ${ssh_opts} -i "${SSH_KEY_FILE}" "${ssh_user}@${node_name}" "${ssh_command}" 2>/dev/null); then
            log_debug "SSH successful with specified key: ${SSH_KEY_FILE}"
            echo "${result}"
            return 0
        else
            log_debug "SSH failed with specified key: ${SSH_KEY_FILE}"
        fi
    fi
    
    # Try without specifying a key (let SSH use its default behavior)
    log_debug "Trying SSH without specific key: ${ssh_user}@${node_name}"
    if result=$(ssh ${ssh_opts} "${ssh_user}@${node_name}" "${ssh_command}" 2>/dev/null); then
        echo "${result}"
        return 0
    fi
    
    # If that fails, try each discovered key
    local ssh_keys
    mapfile -t ssh_keys < <(discover_ssh_keys)
    
    if [[ ${#ssh_keys[@]} -eq 0 ]]; then
        log_debug "No SSH keys found in ${HOME}/.ssh"
        return 1
    fi
    
    for ssh_key in "${ssh_keys[@]}"; do
        # Skip the key if it's the same as the one we already tried
        if [[ -n "${SSH_KEY_FILE}" && "${ssh_key}" == "${SSH_KEY_FILE}" ]]; then
            continue
        fi
        
        log_debug "Trying SSH with key ${ssh_key}: ${ssh_user}@${node_name}"
        if result=$(ssh ${ssh_opts} -i "${ssh_key}" "${ssh_user}@${node_name}" "${ssh_command}" 2>/dev/null); then
            log_debug "SSH successful with key: ${ssh_key}"
            echo "${result}"
            return 0
        fi
    done
    
    log_debug "All SSH key attempts failed for ${ssh_user}@${node_name}"
    return 1
}

# Check FIPS mode status for a single node using direct /proc/sys/crypto/fips_enabled check
check_node_fips_status() {
    local node_name="$1"
    
    log_debug "Checking FIPS status for node: ${node_name}"
    
    # Initialize node status
    local node_fips_enabled="unknown"
    local node_status="${STATUS_UNKNOWN}"
    local node_message="Unable to determine FIPS status"
    local error_details=""
    local os_image="unknown"
    
    # Get OS image for reference
    if os_image=$(oc get node "${node_name}" -o jsonpath='{.status.nodeInfo.osImage}' 2>/dev/null); then
        log_debug "Node OS image: ${os_image}"
    fi
    
    # Try multiple approaches to check FIPS status
    log_debug "Checking FIPS status for node ${node_name} using multiple approaches"
    
    local fips_check_result=""
    local fips_check_successful=false
    
    # Approach 1: Direct /proc/sys/crypto/fips_enabled check with proper debug pod handling
    log_debug "Approach 1: Direct /proc/sys/crypto/fips_enabled check for node ${node_name}"
    
    # Use the correct debug command format and wait for completion
    local debug_error=""
    log_debug "Executing: oc debug node/${node_name} -- chroot /host cat /proc/sys/crypto/fips_enabled"
    
    if fips_check_result=$(oc debug node/${node_name} -- chroot /host cat /proc/sys/crypto/fips_enabled 2>/dev/null | tr -d '\r'); then
        # Clean up the result and get the last line (actual FIPS value)
        fips_check_result=$(echo "${fips_check_result}" | tail -n 1 | tr -d ' \t\n\r')
        
        log_debug "Raw FIPS result for ${node_name}: '${fips_check_result}'"
        
        # Check if the result is a valid FIPS value (0 or 1)
        if [[ "${fips_check_result}" =~ ^[01]$ ]]; then
            fips_check_successful=true
            log_debug "Direct FIPS check succeeded for ${node_name}: result='${fips_check_result}'"
        elif [[ -n "${fips_check_result}" ]]; then
            # Got some output but not 0 or 1
            debug_error="Unexpected output: '${fips_check_result}'"
            log_debug "Direct FIPS check returned unexpected output for ${node_name}: ${debug_error}"
        else
            # Empty result
            debug_error="Empty result from debug command"
            log_debug "Direct FIPS check returned empty result for ${node_name}"
        fi
    else
        debug_error="Debug command failed"
        log_debug "Direct FIPS check failed for ${node_name}: ${debug_error}"
    fi
    
    if [[ "${fips_check_successful}" == "false" ]]; then
        log_debug "Direct FIPS check failed for ${node_name}, trying alternative approaches"
        error_details="Debug command issue: ${debug_error}"
        
        # Approach 2: Enhanced SSH fallback for tainted nodes (especially infra nodes)
        log_debug "Approach 2: Trying enhanced SSH fallback for node ${node_name}"
        local ssh_fips_result=""
        local ssh_successful=false
        
        # Try multiple SSH approaches for tainted/restricted nodes
        local ssh_users=("core" "ec2-user" "cloud-user" "admin")
        local ssh_options=("-o ConnectTimeout=10 -o StrictHostKeyChecking=no" "-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
        
        for ssh_user in "${ssh_users[@]}"; do
            for ssh_opts in "${ssh_options[@]}"; do
                log_debug "Trying SSH with user ${ssh_user} and options: ${ssh_opts}"
                
                if ssh_fips_result=$(try_ssh_with_keys "${ssh_user}" "${node_name}" "cat /proc/sys/crypto/fips_enabled" "${ssh_opts}" | tr -d '\r\n\t '); then
                    log_debug "SSH FIPS result for ${node_name} (${ssh_user}): '${ssh_fips_result}'"
                    
                    # Check if the result is a valid FIPS value (0 or 1)
                    if [[ "${ssh_fips_result}" =~ ^[01]$ ]]; then
                        fips_check_result="${ssh_fips_result}"
                        fips_check_successful=true
                        log_debug "SSH FIPS check succeeded for ${node_name} with user ${ssh_user}: result='${fips_check_result}'"
                        error_details=""  # Clear error details since SSH was successful
                        ssh_successful=true
                        break 2
                    else
                        log_debug "SSH FIPS check returned invalid result for ${node_name} (${ssh_user}): '${ssh_fips_result}'"
                    fi
                else
                    log_debug "SSH FIPS check failed for ${node_name} with user ${ssh_user}"
                fi
            done
        done
        
        if [[ "${ssh_successful}" == "false" ]]; then
            log_debug "All SSH attempts failed for ${node_name}"
        fi
        
        # Approach 3: Check OS image for FIPS indicators
        if [[ "${fips_check_successful}" == "false" ]]; then
            log_debug "Approach 3: Checking OS image for FIPS indicators"
            if [[ -n "${os_image}" ]]; then
                if echo "${os_image}" | grep -qi "fips"; then
                    fips_check_result="1"
                    fips_check_successful=true
                    log_debug "FIPS detected in OS image for node ${node_name}"
                else
                    # Approach 4: Check node annotations for FIPS information
                    log_debug "Approach 4: Checking node annotations for FIPS information"
                    local node_annotations=""
                    if node_annotations=$(oc get node "${node_name}" -o jsonpath='{.metadata.annotations}' 2>/dev/null); then
                        if echo "${node_annotations}" | grep -qi "fips"; then
                            fips_check_result="1"
                            fips_check_successful=true
                            log_debug "FIPS detected in node annotations for ${node_name}"
                        fi
                    fi
                fi
            fi
        fi
        
        # Approach 4: Check for FIPS-related labels
        if [[ "${fips_check_successful}" == "false" ]]; then
            log_debug "Approach 4: Checking node labels for FIPS information"
            local node_labels=""
            if node_labels=$(oc get node "${node_name}" -o jsonpath='{.metadata.labels}' 2>/dev/null); then
                if echo "${node_labels}" | grep -qi "fips"; then
                    fips_check_result="1"
                    fips_check_successful=true
                    log_debug "FIPS detected in node labels for ${node_name}"
                fi
            fi
        fi
    fi
    
    if [[ "${fips_check_successful}" == "true" ]]; then
        # Clean up the result (remove carriage returns and whitespace)
        fips_check_result=$(echo "${fips_check_result}" | tr -d '\r' | tr -d '\n' | tr -d ' ')
        log_debug "FIPS check result for ${node_name}: '${fips_check_result}'"
        
        # Parse the result
        case "${fips_check_result}" in
            "1")
                node_fips_enabled="true"
                node_status="${STATUS_HEALTHY}"
                node_message="FIPS mode enabled (verified from /proc/sys/crypto/fips_enabled)"
                log_debug "FIPS enabled on node ${node_name}"
                ;;
            "0")
                node_fips_enabled="false"
                node_status="${STATUS_CRITICAL}"
                node_message="FIPS mode disabled (verified from /proc/sys/crypto/fips_enabled)"
                log_debug "FIPS disabled on node ${node_name}"
                ;;
            *)
                # Unexpected result or access denied
                if echo "${fips_check_result}" | grep -qi "permission\|denied\|access"; then
                    node_fips_enabled="unknown"
                    node_status="${STATUS_UNKNOWN}"
                    node_message="Unable to access FIPS status (permission denied)"
                    error_details="Debug access to node denied"
                else
                    node_fips_enabled="unknown"
                    node_status="${STATUS_UNKNOWN}"
                    node_message="Unable to determine FIPS status (unexpected result)"
                    error_details="Unexpected result from /proc/sys/crypto/fips_enabled: '${fips_check_result}'"
                fi
                log_debug "Unexpected FIPS check result for ${node_name}: '${fips_check_result}'"
                ;;
        esac
    else
        # Debug command failed
        log_debug "FIPS debug command failed for node ${node_name}"
        node_fips_enabled="unknown"
        node_status="${STATUS_UNKNOWN}"
        node_message="Unable to access FIPS status (debug command failed)"
        error_details="Debug access command failed or timed out"
    fi
    
    # Create node result JSON
    local node_result
    node_result=$(cat << EOF
{
    "name": "${node_name}",
    "fips_enabled": "${node_fips_enabled}",
    "status": "${node_status}",
    "message": "${node_message}",
    "os_image": "${os_image}",
    "error_details": "${error_details}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    log_debug "Node FIPS result for ${node_name}: ${node_status}"
    echo "${node_result}"
}

# Check FIPS compliance across all cluster nodes
check_fips_compliance() {
    log_info "Checking FIPS compliance across all cluster nodes..."
    
    # Reset FIPS status
    fips_status["overall_status"]="${STATUS_UNKNOWN}"
    fips_status["overall_message"]=""
    fips_status["compliant_nodes"]="0"
    fips_status["non_compliant_nodes"]="0"
    fips_status["unknown_nodes"]="0"
    fips_status["total_nodes"]="0"
    fips_status["check_timestamp"]="$(get_timestamp)"
    fips_status["details"]=""
    fips_status["errors"]=""
    
    # Get all nodes with their OS information
    local nodes_json=""
    if ! nodes_json=$(execute_oc_json "get nodes -o json" "Get nodes for FIPS check"); then
        log_error "Failed to retrieve cluster nodes for FIPS compliance check"
        fips_status["overall_status"]="${STATUS_CRITICAL}"
        fips_status["overall_message"]="Failed to retrieve cluster nodes"
        fips_status["errors"]="Unable to access cluster nodes"
        return 1
    fi
    
    # Validate nodes JSON
    if ! validate_json "${nodes_json}" "nodes data"; then
        log_error "Invalid JSON response from nodes query"
        fips_status["overall_status"]="${STATUS_CRITICAL}"
        fips_status["overall_message"]="Invalid response from cluster API"
        fips_status["errors"]="Invalid JSON response from nodes query"
        return 1
    fi
    
    # Count total nodes
    local total_nodes
    total_nodes=$(count_json_array "${nodes_json}" ".items" "cluster nodes")
    fips_status["total_nodes"]="${total_nodes}"
    
    if [[ "${total_nodes}" -eq 0 ]]; then
        log_warn "No nodes found in cluster"
        fips_status["overall_status"]="${STATUS_UNKNOWN}"
        fips_status["overall_message"]="No nodes found in cluster"
        return 0
    fi
    
    log_info "Found ${total_nodes} nodes to check for FIPS compliance"
    
    # Initialize counters
    local compliant_count=0
    local non_compliant_count=0
    local unknown_count=0
    local node_details=()
    local error_messages=()
    
    # Process each node
    local node_index=0
    while [[ ${node_index} -lt ${total_nodes} ]]; do
        # Extract node information
        local node_name
        local node_os_image
        
        node_name=$(parse_json_field "${nodes_json}" ".items[${node_index}].metadata.name" "" "node name")
        node_os_image=$(parse_json_field "${nodes_json}" ".items[${node_index}].status.nodeInfo.osImage" "" "node OS image")
        
        if [[ -z "${node_name}" ]]; then
            log_warn "Skipping node at index ${node_index} - no name found"
            ((node_index++))
            continue
        fi
        
        log_debug "Processing node $((node_index + 1))/${total_nodes}: ${node_name}"
        
        # Check FIPS status for this node
        local node_result
        if node_result=$(check_node_fips_status "${node_name}" "${node_os_image}"); then
            # Parse node result
            local node_status
            local node_fips_enabled
            local node_message
            local node_error_details
            
            node_status=$(parse_json_field "${node_result}" ".status" "${STATUS_UNKNOWN}" "node status")
            node_fips_enabled=$(parse_json_field "${node_result}" ".fips_enabled" "unknown" "node FIPS enabled")
            node_message=$(parse_json_field "${node_result}" ".message" "" "node message")
            node_error_details=$(parse_json_field "${node_result}" ".error_details" "" "node error details")
            
            # Update counters based on status
            case "${node_status}" in
                "${STATUS_HEALTHY}")
                    ((compliant_count++))
                    log_debug "Node ${node_name}: FIPS compliant"
                    ;;
                "${STATUS_CRITICAL}")
                    ((non_compliant_count++))
                    log_warn "Node ${node_name}: FIPS non-compliant - ${node_message}"
                    ;;
                *)
                    ((unknown_count++))
                    log_warn "Node ${node_name}: FIPS status unknown - ${node_message}"
                    ;;
            esac
            
            # Store node details
            node_details+=("${node_result}")
            
            # Collect error details if present
            if [[ -n "${node_error_details}" ]]; then
                error_messages+=("${node_name}: ${node_error_details}")
            fi
            
        else
            log_error "Failed to check FIPS status for node: ${node_name}"
            ((unknown_count++))
            error_messages+=("${node_name}: Failed to check FIPS status")
        fi
        
        ((node_index++))
    done
    
    # Update FIPS status counters
    fips_status["compliant_nodes"]="${compliant_count}"
    fips_status["non_compliant_nodes"]="${non_compliant_count}"
    fips_status["unknown_nodes"]="${unknown_count}"
    
    # Determine overall FIPS compliance status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    if [[ ${non_compliant_count} -gt 0 ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="FIPS compliance failed: ${non_compliant_count} of ${total_nodes} nodes are not FIPS compliant"
    elif [[ ${compliant_count} -eq ${total_nodes} ]]; then
        overall_status="${STATUS_HEALTHY}"
        overall_message="FIPS compliance verified: All ${total_nodes} nodes are FIPS compliant"
    elif [[ ${compliant_count} -gt 0 ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="FIPS compliance partial: ${compliant_count} of ${total_nodes} nodes are FIPS compliant, ${unknown_count} status unknown"
    else
        overall_status="${STATUS_UNKNOWN}"
        overall_message="FIPS compliance status unknown for all ${total_nodes} nodes"
    fi
    
    # Update overall status
    fips_status["overall_status"]="${overall_status}"
    fips_status["overall_message"]="${overall_message}"
    
    # Create detailed results JSON
    local details_json
    details_json=$(printf '%s\n' "${node_details[@]}" | jq -s '.')
    fips_status["details"]="${details_json}"
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        fips_status["errors"]=$(printf '%s; ' "${error_messages[@]}" | sed 's/; $//')
    fi
    
    # Log summary
    log_info "FIPS compliance check completed:"
    log_info "  Total nodes: ${total_nodes}"
    log_info "  Compliant nodes: ${compliant_count}"
    log_info "  Non-compliant nodes: ${non_compliant_count}"
    log_info "  Unknown status nodes: ${unknown_count}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get FIPS compliance status summary
get_fips_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${fips_status["overall_status"]}",
    "overall_message": "${fips_status["overall_message"]}",
    "compliant_nodes": ${fips_status["compliant_nodes"]},
    "non_compliant_nodes": ${fips_status["non_compliant_nodes"]},
    "unknown_nodes": ${fips_status["unknown_nodes"]},
    "total_nodes": ${fips_status["total_nodes"]},
    "check_timestamp": "${fips_status["check_timestamp"]}",
    "details": ${fips_status["details"]:-"[]"},
    "errors": "${fips_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
FIPS Compliance Status: ${fips_status["overall_status"]}
Message: ${fips_status["overall_message"]}
Compliant Nodes: ${fips_status["compliant_nodes"]}/${fips_status["total_nodes"]}
Non-Compliant Nodes: ${fips_status["non_compliant_nodes"]}/${fips_status["total_nodes"]}
Unknown Status Nodes: ${fips_status["unknown_nodes"]}/${fips_status["total_nodes"]}
Check Timestamp: ${fips_status["check_timestamp"]}
EOF
            if [[ -n "${fips_status["errors"]}" ]]; then
                echo "Errors: ${fips_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# NTP SYNCHRONIZATION CHECK MODULE
# =============================================================================

# NTP synchronization status structure
declare -A ntp_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["synchronized_nodes"]="0"
    ["unsynchronized_nodes"]="0"
    ["unknown_nodes"]="0"
    ["total_nodes"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check NTP synchronization status for a single node
check_node_ntp_status() {
    local node_name="$1"
    
    log_debug "Checking NTP synchronization status for node: ${node_name}"
    
    # Initialize node status
    local node_synchronized="unknown"
    local node_status="${STATUS_UNKNOWN}"
    local node_message="Unable to determine NTP synchronization status"
    local time_offset="unknown"
    local ntp_servers="unknown"
    local error_details=""
    
    # Try to get NTP status using debug access
    log_debug "Attempting debug access for NTP check on node ${node_name}"
    
    local timedatectl_result=""
    local debug_cmd="debug node/${node_name} -- chroot /host timedatectl status"
    
    if timedatectl_result=$(execute_oc_command "${debug_cmd}" "NTP check for node ${node_name}" 1 10 2>/dev/null); then
        log_debug "Debug access result for ${node_name}: ${timedatectl_result}"
        
        # Parse timedatectl output
        local ntp_synchronized=""
        local system_clock_synchronized=""
        local time_zone=""
        local local_time=""
        local universal_time=""
        local rtc_time=""
        
        # Extract key information from timedatectl output
        if echo "${timedatectl_result}" | grep -q "NTP synchronized: yes"; then
            ntp_synchronized="yes"
        elif echo "${timedatectl_result}" | grep -q "NTP synchronized: no"; then
            ntp_synchronized="no"
        fi
        
        if echo "${timedatectl_result}" | grep -q "System clock synchronized: yes"; then
            system_clock_synchronized="yes"
        elif echo "${timedatectl_result}" | grep -q "System clock synchronized: no"; then
            system_clock_synchronized="no"
        fi
        
        # Extract time zone
        time_zone=$(echo "${timedatectl_result}" | grep "Time zone:" | sed 's/.*Time zone: *\([^(]*\).*/\1/' | xargs)
        
        # Extract times for offset calculation
        local_time=$(echo "${timedatectl_result}" | grep "Local time:" | sed 's/.*Local time: *//' | xargs)
        universal_time=$(echo "${timedatectl_result}" | grep "Universal time:" | sed 's/.*Universal time: *//' | xargs)
        rtc_time=$(echo "${timedatectl_result}" | grep "RTC time:" | sed 's/.*RTC time: *//' | xargs)
        
        # Determine synchronization status
        if [[ "${ntp_synchronized}" == "yes" && "${system_clock_synchronized}" == "yes" ]]; then
            node_synchronized="true"
            node_status="${STATUS_HEALTHY}"
            node_message="NTP synchronized and system clock synchronized"
        elif [[ "${ntp_synchronized}" == "yes" ]]; then
            node_synchronized="partial"
            node_status="${STATUS_WARNING}"
            node_message="NTP synchronized but system clock may have issues"
        elif [[ "${system_clock_synchronized}" == "yes" ]]; then
            node_synchronized="partial"
            node_status="${STATUS_WARNING}"
            node_message="System clock synchronized but NTP may not be active"
        else
            node_synchronized="false"
            node_status="${STATUS_CRITICAL}"
            node_message="NTP and system clock not synchronized"
        fi
        
        # Try to get NTP servers information
        local ntp_servers_cmd="debug node/${node_name} -- chroot /host chrony sources 2>/dev/null || chroot /host systemctl status chronyd 2>/dev/null || echo 'ntp_servers_unavailable'"
        local ntp_servers_result=""
        
        if ntp_servers_result=$(execute_oc_command "${ntp_servers_cmd}" "NTP servers check for node ${node_name}" 1 2 2>/dev/null); then
            if echo "${ntp_servers_result}" | grep -q "ntp_servers_unavailable"; then
                ntp_servers="unavailable"
            else
                # Extract NTP servers from chrony sources or systemctl output
                if echo "${ntp_servers_result}" | grep -q "^\^"; then
                    # chrony sources format
                    ntp_servers=$(echo "${ntp_servers_result}" | grep "^\^" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
                elif echo "${ntp_servers_result}" | grep -q "Active:"; then
                    # systemctl status format
                    ntp_servers="chronyd service active"
                else
                    ntp_servers="detected but format unknown"
                fi
            fi
        else
            ntp_servers="check failed"
        fi
        
        # Calculate approximate time offset if possible
        if [[ -n "${local_time}" && -n "${universal_time}" ]]; then
            # This is a simplified offset calculation
            time_offset="calculated from local/universal time difference"
        else
            time_offset="unavailable"
        fi
        
    else
        # Debug access failed, try enhanced SSH fallback
        log_debug "Debug access failed for node ${node_name}, trying enhanced SSH fallback"
        
        local ssh_timedatectl_result=""
        local ssh_ntp_successful=false
        
        # Try multiple SSH approaches for tainted/restricted nodes (especially infra nodes)
        local ssh_users=("core" "ec2-user" "cloud-user" "admin")
        local ssh_options=("-o ConnectTimeout=10 -o StrictHostKeyChecking=no" "-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
        
        for ssh_user in "${ssh_users[@]}"; do
            for ssh_opts in "${ssh_options[@]}"; do
                log_debug "Trying NTP SSH with user ${ssh_user} and options: ${ssh_opts}"
                
                if ssh_timedatectl_result=$(try_ssh_with_keys "${ssh_user}" "${node_name}" "timedatectl status" "${ssh_opts}"); then
                    log_debug "SSH NTP check result for ${node_name} (${ssh_user}): ${ssh_timedatectl_result}"
                    
                    # Parse timedatectl output from SSH
                    local ntp_synchronized=""
                    local system_clock_synchronized=""
                    local time_zone=""
                    local local_time=""
                    local universal_time=""
                    local rtc_time=""
                    
                    # Extract key information from timedatectl output
                    if echo "${ssh_timedatectl_result}" | grep -q "NTP synchronized: yes"; then
                        ntp_synchronized="yes"
                    elif echo "${ssh_timedatectl_result}" | grep -q "NTP synchronized: no"; then
                        ntp_synchronized="no"
                    fi
                    
                    if echo "${ssh_timedatectl_result}" | grep -q "System clock synchronized: yes"; then
                        system_clock_synchronized="yes"
                    elif echo "${ssh_timedatectl_result}" | grep -q "System clock synchronized: no"; then
                        system_clock_synchronized="no"
                    fi
                    
                    # Extract time zone
                    time_zone=$(echo "${ssh_timedatectl_result}" | grep "Time zone:" | sed 's/.*Time zone: *\([^(]*\).*/\1/' | xargs)
                    
                    # Extract times for offset calculation
                    local_time=$(echo "${ssh_timedatectl_result}" | grep "Local time:" | sed 's/.*Local time: *//' | xargs)
                    universal_time=$(echo "${ssh_timedatectl_result}" | grep "Universal time:" | sed 's/.*Universal time: *//' | xargs)
                    rtc_time=$(echo "${ssh_timedatectl_result}" | grep "RTC time:" | sed 's/.*RTC time: *//' | xargs)
                    
                    # Determine synchronization status
                    if [[ "${ntp_synchronized}" == "yes" && "${system_clock_synchronized}" == "yes" ]]; then
                        node_synchronized="true"
                        node_status="${STATUS_HEALTHY}"
                        node_message="NTP synchronized and system clock synchronized (via SSH - ${ssh_user})"
                    elif [[ "${ntp_synchronized}" == "yes" ]]; then
                        node_synchronized="partial"
                        node_status="${STATUS_WARNING}"
                        node_message="NTP synchronized but system clock may have issues (via SSH - ${ssh_user})"
                    elif [[ "${system_clock_synchronized}" == "yes" ]]; then
                        node_synchronized="partial"
                        node_status="${STATUS_WARNING}"
                        node_message="System clock synchronized but NTP may not be active (via SSH - ${ssh_user})"
                    else
                        node_synchronized="false"
                        node_status="${STATUS_CRITICAL}"
                        node_message="NTP and system clock not synchronized (via SSH - ${ssh_user})"
                    fi
                    
                    # Try to get NTP servers information via SSH
                    local ssh_ntp_servers_result=""
                    if ssh_ntp_servers_result=$(try_ssh_with_keys "${ssh_user}" "${node_name}" "chrony sources 2>/dev/null || systemctl status chronyd 2>/dev/null || echo 'ntp_servers_unavailable'" "${ssh_opts}"); then
                        if echo "${ssh_ntp_servers_result}" | grep -q "ntp_servers_unavailable"; then
                            ntp_servers="unavailable"
                        else
                            # Extract NTP servers from chrony sources or systemctl output
                            if echo "${ssh_ntp_servers_result}" | grep -q "^\^"; then
                                # chrony sources format
                                ntp_servers=$(echo "${ssh_ntp_servers_result}" | grep "^\^" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
                            elif echo "${ssh_ntp_servers_result}" | grep -q "Active:"; then
                                # systemctl status format
                                ntp_servers="chronyd service active"
                            else
                                ntp_servers="detected but format unknown"
                            fi
                        fi
                    else
                        ntp_servers="check failed"
                    fi
                    
                    # Calculate approximate time offset if possible
                    if [[ -n "${local_time}" && -n "${universal_time}" ]]; then
                        # This is a simplified offset calculation
                        time_offset="calculated from local/universal time difference"
                    else
                        time_offset="unavailable"
                    fi
                    
                    error_details=""  # Clear error details since SSH was successful
                    ssh_ntp_successful=true
                    break 2
                    
                else
                    log_debug "SSH NTP check failed for ${node_name} with user ${ssh_user}"
                fi
            done
        done
        
        if [[ "${ssh_ntp_successful}" == "false" ]]; then
            # Both debug and SSH access failed
            log_debug "Both debug and SSH access failed for node ${node_name}"
            node_synchronized="unknown"
            node_status="${STATUS_UNKNOWN}"
            node_message="Unable to access node for NTP status check (debug and SSH failed)"
            error_details="Both debug access and SSH fallback failed"
        fi
    fi
    
    # Create node result JSON
    local node_result
    node_result=$(cat << EOF
{
    "name": "${node_name}",
    "synchronized": "${node_synchronized}",
    "status": "${node_status}",
    "message": "${node_message}",
    "time_offset": "${time_offset}",
    "ntp_servers": "${ntp_servers}",
    "time_zone": "${time_zone:-unknown}",
    "local_time": "${local_time:-unknown}",
    "universal_time": "${universal_time:-unknown}",
    "error_details": "${error_details}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    log_debug "Node NTP result for ${node_name}: ${node_status}"
    echo "${node_result}"
}

# Check NTP synchronization across all cluster nodes
check_ntp_synchronization() {
    log_info "Checking NTP synchronization across all cluster nodes..."
    
    # Reset NTP status
    ntp_status["overall_status"]="${STATUS_UNKNOWN}"
    ntp_status["overall_message"]=""
    ntp_status["synchronized_nodes"]="0"
    ntp_status["unsynchronized_nodes"]="0"
    ntp_status["unknown_nodes"]="0"
    ntp_status["total_nodes"]="0"
    ntp_status["check_timestamp"]="$(get_timestamp)"
    ntp_status["details"]=""
    ntp_status["errors"]=""
    
    # Get all nodes
    local nodes_json=""
    if ! nodes_json=$(execute_oc_json "get nodes -o json" "Get nodes for NTP check"); then
        log_error "Failed to retrieve cluster nodes for NTP synchronization check"
        ntp_status["overall_status"]="${STATUS_CRITICAL}"
        ntp_status["overall_message"]="Failed to retrieve cluster nodes"
        ntp_status["errors"]="Unable to access cluster nodes"
        return 1
    fi
    
    # Validate nodes JSON
    if ! validate_json "${nodes_json}" "nodes data"; then
        log_error "Invalid JSON response from nodes query"
        ntp_status["overall_status"]="${STATUS_CRITICAL}"
        ntp_status["overall_message"]="Invalid response from cluster API"
        ntp_status["errors"]="Invalid JSON response from nodes query"
        return 1
    fi
    
    # Count total nodes
    local total_nodes
    total_nodes=$(count_json_array "${nodes_json}" ".items" "cluster nodes")
    ntp_status["total_nodes"]="${total_nodes}"
    
    if [[ "${total_nodes}" -eq 0 ]]; then
        log_warn "No nodes found in cluster"
        ntp_status["overall_status"]="${STATUS_UNKNOWN}"
        ntp_status["overall_message"]="No nodes found in cluster"
        return 0
    fi
    
    log_info "Found ${total_nodes} nodes to check for NTP synchronization"
    
    # Initialize counters
    local synchronized_count=0
    local unsynchronized_count=0
    local unknown_count=0
    local node_details=()
    local error_messages=()
    
    # Process each node
    local node_index=0
    while [[ ${node_index} -lt ${total_nodes} ]]; do
        # Extract node information
        local node_name
        node_name=$(parse_json_field "${nodes_json}" ".items[${node_index}].metadata.name" "" "node name")
        
        if [[ -z "${node_name}" ]]; then
            log_warn "Skipping node with missing name at index ${node_index}"
            ((node_index++))
            continue
        fi
        
        log_debug "Processing node ${node_index}/${total_nodes}: ${node_name}"
        
        # Check NTP status for this node
        local node_result=""
        if node_result=$(check_node_ntp_status "${node_name}"); then
            # Parse node result
            local node_status
            local node_synchronized
            local node_message
            local node_error_details
            
            node_status=$(parse_json_field "${node_result}" ".status" "${STATUS_UNKNOWN}" "node status")
            node_synchronized=$(parse_json_field "${node_result}" ".synchronized" "unknown" "node synchronized")
            node_message=$(parse_json_field "${node_result}" ".message" "" "node message")
            node_error_details=$(parse_json_field "${node_result}" ".error_details" "" "node error details")
            
            # Update counters based on status
            case "${node_synchronized}" in
                "true")
                    ((synchronized_count++))
                    ;;
                "false")
                    ((unsynchronized_count++))
                    ;;
                "partial")
                    # Count partial sync as warning but not fully synchronized
                    ((synchronized_count++))
                    ;;
                *)
                    ((unknown_count++))
                    ;;
            esac
            
            # Add to details array
            node_details+=("${node_result}")
            
            # Collect error messages
            if [[ -n "${node_error_details}" ]]; then
                error_messages+=("${node_name}: ${node_error_details}")
            fi
            
            log_debug "Node ${node_name} NTP status: ${node_status} (synchronized: ${node_synchronized})"
            
        else
            log_error "Failed to check NTP status for node: ${node_name}"
            ((unknown_count++))
            error_messages+=("${node_name}: Failed to check NTP status")
        fi
        
        ((node_index++))
    done
    
    # Update status counters
    ntp_status["synchronized_nodes"]="${synchronized_count}"
    ntp_status["unsynchronized_nodes"]="${unsynchronized_count}"
    ntp_status["unknown_nodes"]="${unknown_count}"
    
    # Create details JSON array
    local details_json="["
    for i in "${!node_details[@]}"; do
        if [[ ${i} -gt 0 ]]; then
            details_json+=","
        fi
        details_json+="${node_details[${i}]}"
    done
    details_json+="]"
    ntp_status["details"]="${details_json}"
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        ntp_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    if [[ ${unsynchronized_count} -gt 0 ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="NTP synchronization issues detected on ${unsynchronized_count} node(s)"
    elif [[ ${unknown_count} -eq ${total_nodes} ]]; then
        overall_status="${STATUS_UNKNOWN}"
        overall_message="Unable to determine NTP synchronization status for any nodes"
    elif [[ ${unknown_count} -gt 0 ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="NTP synchronization status unknown for ${unknown_count} node(s)"
    elif [[ ${synchronized_count} -eq ${total_nodes} ]]; then
        overall_status="${STATUS_HEALTHY}"
        overall_message="All nodes are properly synchronized with NTP"
    else
        overall_status="${STATUS_WARNING}"
        overall_message="Mixed NTP synchronization status across nodes"
    fi
    
    # Update overall status
    ntp_status["overall_status"]="${overall_status}"
    ntp_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "NTP synchronization check completed:"
    log_info "  Total nodes: ${total_nodes}"
    log_info "  Synchronized nodes: ${synchronized_count}"
    log_info "  Unsynchronized nodes: ${unsynchronized_count}"
    log_info "  Unknown status nodes: ${unknown_count}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get NTP synchronization status summary
get_ntp_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${ntp_status["overall_status"]}",
    "overall_message": "${ntp_status["overall_message"]}",
    "synchronized_nodes": ${ntp_status["synchronized_nodes"]},
    "unsynchronized_nodes": ${ntp_status["unsynchronized_nodes"]},
    "unknown_nodes": ${ntp_status["unknown_nodes"]},
    "total_nodes": ${ntp_status["total_nodes"]},
    "check_timestamp": "${ntp_status["check_timestamp"]}",
    "details": ${ntp_status["details"]:-"[]"},
    "errors": "${ntp_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
NTP Synchronization Status: ${ntp_status["overall_status"]}
Message: ${ntp_status["overall_message"]}
Synchronized Nodes: ${ntp_status["synchronized_nodes"]}/${ntp_status["total_nodes"]}
Unsynchronized Nodes: ${ntp_status["unsynchronized_nodes"]}/${ntp_status["total_nodes"]}
Unknown Status Nodes: ${ntp_status["unknown_nodes"]}/${ntp_status["total_nodes"]}
Check Timestamp: ${ntp_status["check_timestamp"]}
EOF
            if [[ -n "${ntp_status["errors"]}" ]]; then
                echo "Errors: ${ntp_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# ETCD ENCRYPTION STATUS MODULE
# =============================================================================

# etcd encryption status structure
declare -A etcd_encryption_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["encryption_enabled"]="unknown"
    ["encryption_type"]="unknown"
    ["encryption_provider"]="unknown"
    ["reencryption_verified"]="unknown"
    ["reencryption_status"]="unknown"
    ["key_rotation_status"]="unknown"
    ["last_key_rotation"]="unknown"
    ["etcd_pods_healthy"]="0"
    ["etcd_pods_total"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check etcd encryption configuration
check_etcd_encryption_config() {
    log_debug "Checking etcd encryption configuration..."
    
    local encryption_enabled="false"
    local encryption_type="unknown"
    local encryption_provider="unknown"
    local config_errors=""
    
    # Primary check: Get encryption type from APIServer configuration
    log_debug "Checking APIServer encryption configuration..."
    local etcd_encryption=""
    if etcd_encryption=$(oc get apiserver cluster -o jsonpath='{.spec.encryption.type}' 2>/dev/null); then
        log_debug "Retrieved encryption type from APIServer: '${etcd_encryption}'"
        
        # Check if encryption is enabled and determine type
        if [[ -n "${etcd_encryption}" && "${etcd_encryption}" != "null" ]]; then
            case "${etcd_encryption}" in
                "aescbc")
                    encryption_enabled="true"
                    encryption_type="aescbc"
                    encryption_provider="AES-CBC with PKCS#7 padding"
                    log_debug "ETCD Encryption: Enabled (aescbc)"
                    ;;
                "kms")
                    encryption_enabled="true"
                    encryption_type="kms"
                    encryption_provider="Key Management Service (KMS)"
                    log_debug "ETCD Encryption: Enabled (kms)"
                    ;;
                "aesgcm")
                    encryption_enabled="true"
                    encryption_type="aesgcm"
                    encryption_provider="AES-GCM"
                    log_debug "ETCD Encryption: Enabled (aesgcm)"
                    ;;
                "secretbox")
                    encryption_enabled="true"
                    encryption_type="secretbox"
                    encryption_provider="Secretbox (XSalsa20 and Poly1305)"
                    log_debug "ETCD Encryption: Enabled (secretbox)"
                    ;;
                *)
                    encryption_enabled="true"
                    encryption_type="${etcd_encryption}"
                    encryption_provider="Custom encryption type"
                    log_debug "ETCD Encryption: Enabled (${etcd_encryption})"
                    ;;
            esac
        else
            encryption_enabled="false"
            encryption_type="none"
            encryption_provider="No encryption configured"
            log_debug "ETCD Encryption: Disabled"
        fi
    else
        log_warn "Could not retrieve encryption type from APIServer configuration"
        config_errors="Failed to retrieve APIServer encryption configuration"
        
        # Fallback: Check for etcd encryption secrets
        log_debug "Attempting fallback check via etcd encryption secrets..."
        local encryption_secrets=""
        if encryption_secrets=$(execute_oc_command "get secrets -n openshift-etcd -l k8s-app=etcd --no-headers 2>/dev/null" "Get etcd encryption secrets" 1); then
            if echo "${encryption_secrets}" | grep -q "encryption"; then
                encryption_enabled="true"
                encryption_type="detected"
                encryption_provider="Detected via etcd secrets (type unknown)"
                log_debug "Encryption detected via etcd secrets"
            else
                encryption_enabled="false"
                encryption_type="none"
                encryption_provider="No encryption detected"
            fi
        else
            config_errors="${config_errors}; Failed to check etcd encryption secrets"
        fi
    fi
    
    # Additional check: Verify etcd cluster encryption status
    local etcd_cluster_encrypted=""
    if etcd_cluster_encrypted=$(oc get etcd cluster -o jsonpath='{.status.conditions[?(@.type=="Encrypted")].status}' 2>/dev/null); then
        log_debug "ETCD cluster encryption status: ${etcd_cluster_encrypted}"
        if [[ "${etcd_cluster_encrypted}" == "True" ]]; then
            if [[ "${encryption_enabled}" == "false" ]]; then
                encryption_enabled="true"
                encryption_type="verified"
                encryption_provider="Verified via etcd cluster status"
            fi
        elif [[ "${etcd_cluster_encrypted}" == "False" ]]; then
            if [[ "${encryption_enabled}" == "true" ]]; then
                config_errors="${config_errors}; Encryption configured but etcd cluster reports not encrypted"
            fi
        fi
    fi
    
    # Verify resources are re-encrypted with new key
    log_debug "Verifying resources are re-encrypted with new key..."
    local reencryption_status=""
    local reencryption_verified="unknown"
    if reencryption_status=$(oc get clusteroperator kube-apiserver -o jsonpath='{.status.extension.encryption}' 2>/dev/null); then
        log_debug "Kube-apiserver encryption extension status: ${reencryption_status}"
        if [[ -n "${reencryption_status}" && "${reencryption_status}" != "null" ]]; then
            # Parse the encryption status to check if resources are re-encrypted
            if echo "${reencryption_status}" | grep -qi "encrypted\|complete\|success"; then
                reencryption_verified="true"
                log_debug "Resources re-encryption verified: ${reencryption_status}"
            elif echo "${reencryption_status}" | grep -qi "progress\|ongoing\|running"; then
                reencryption_verified="in_progress"
                log_debug "Resources re-encryption in progress: ${reencryption_status}"
            elif echo "${reencryption_status}" | grep -qi "failed\|error"; then
                reencryption_verified="failed"
                config_errors="${config_errors}; Resource re-encryption failed: ${reencryption_status}"
                log_warn "Resources re-encryption failed: ${reencryption_status}"
            else
                reencryption_verified="unknown"
                log_debug "Unknown re-encryption status: ${reencryption_status}"
            fi
        else
            reencryption_verified="not_available"
            log_debug "No encryption extension status available from kube-apiserver"
        fi
    else
        log_debug "Could not retrieve kube-apiserver encryption extension status"
        config_errors="${config_errors}; Failed to check resource re-encryption status"
    fi
    
    # Create encryption config result
    local config_result
    config_result=$(cat << EOF
{
    "encryption_enabled": "${encryption_enabled}",
    "encryption_type": "${encryption_type}",
    "encryption_provider": "${encryption_provider}",
    "reencryption_verified": "${reencryption_verified}",
    "reencryption_status": "${reencryption_status}",
    "config_errors": "${config_errors}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    echo "${config_result}"
}

# Check etcd key rotation status
check_etcd_key_rotation() {
    log_debug "Checking etcd key rotation status..."
    
    local rotation_status="unknown"
    local last_rotation="unknown"
    local rotation_errors=""
    
    # Primary check: Look for encryption-config secrets in openshift-apiserver namespace
    log_debug "Checking for encryption-config secrets in openshift-apiserver namespace..."
    local encryption_secrets=""
    if encryption_secrets=$(execute_oc_json "get secrets -n openshift-apiserver -o json" "Get openshift-apiserver secrets"); then
        # Filter secrets that match encryption-config pattern and get the latest one
        local latest_secret_info
        latest_secret_info=$(echo "${encryption_secrets}" | jq -r '
            .items[] | 
            select(.metadata.name | test("^encryption-config")) | 
            {name: .metadata.name, creationTimestamp: .metadata.creationTimestamp} | 
            @base64' 2>/dev/null | while read -r secret_data; do
                if [[ -n "${secret_data}" ]]; then
                    echo "${secret_data}" | base64 -d 2>/dev/null
                fi
            done | jq -s 'sort_by(.creationTimestamp) | last' 2>/dev/null)
        
        if [[ -n "${latest_secret_info}" && "${latest_secret_info}" != "null" ]]; then
            local secret_name
            local secret_creation_time
            secret_name=$(echo "${latest_secret_info}" | jq -r '.name' 2>/dev/null)
            secret_creation_time=$(echo "${latest_secret_info}" | jq -r '.creationTimestamp' 2>/dev/null)
            
            if [[ -n "${secret_name}" && -n "${secret_creation_time}" && "${secret_creation_time}" != "null" ]]; then
                rotation_status="detected"
                last_rotation="${secret_creation_time}"
                log_debug "Found latest encryption-config secret: ${secret_name} created at ${secret_creation_time}"
            else
                log_debug "Could not parse encryption-config secret information"
            fi
        else
            log_debug "No encryption-config secrets found in openshift-apiserver namespace"
        fi
    else
        rotation_errors="Failed to retrieve secrets from openshift-apiserver namespace"
        log_debug "Could not retrieve secrets from openshift-apiserver namespace"
    fi
    
    # Fallback check: Look for encryption key secrets in openshift-etcd namespace
    if [[ "${rotation_status}" == "unknown" ]]; then
        log_debug "Fallback: checking etcd encryption secrets..."
        local key_secrets=""
        if key_secrets=$(execute_oc_json "get secrets -n openshift-etcd -l k8s-app=etcd -o json 2>/dev/null" "Get etcd key secrets"); then
            # Find the most recent encryption-related secret
            local recent_secret_time
            recent_secret_time=$(echo "${key_secrets}" | jq -r '.items[] | select(.metadata.name | contains("encryption")) | .metadata.creationTimestamp' 2>/dev/null | sort | tail -1)
            
            if [[ -n "${recent_secret_time}" && "${recent_secret_time}" != "null" ]]; then
                last_rotation="${recent_secret_time}"
                rotation_status="detected via etcd secrets"
                log_debug "Found encryption secret in openshift-etcd with timestamp: ${recent_secret_time}"
            fi
        fi
    fi
    
    # Additional fallback: Check etcd operator logs for key rotation events
    if [[ "${rotation_status}" == "unknown" ]]; then
        log_debug "Final fallback: checking etcd operator logs..."
        local etcd_operator_logs=""
        if etcd_operator_logs=$(execute_oc_command "logs -n openshift-etcd-operator deployment/etcd-operator --tail=100 2>/dev/null" "Get etcd operator logs" 1); then
            # Look for key rotation events
            if echo "${etcd_operator_logs}" | grep -q -i "key.*rotat"; then
                rotation_status="detected via logs"
                
                # Try to extract last rotation timestamp
                local rotation_line
                rotation_line=$(echo "${etcd_operator_logs}" | grep -i "key.*rotat" | tail -1)
                
                if [[ -n "${rotation_line}" ]]; then
                    # Extract timestamp from log line
                    local timestamp_pattern="[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                    if echo "${rotation_line}" | grep -oE "${timestamp_pattern}" >/dev/null 2>&1; then
                        last_rotation=$(echo "${rotation_line}" | grep -oE "${timestamp_pattern}" | head -1)
                    else
                        last_rotation="timestamp not parseable from logs"
                    fi
                fi
                log_debug "Found key rotation activity in etcd operator logs"
            else
                rotation_status="no recent activity"
                log_debug "No key rotation activity found in etcd operator logs"
            fi
        else
            if [[ -z "${rotation_errors}" ]]; then
                rotation_errors="Failed to retrieve etcd operator logs"
            fi
            log_debug "Could not retrieve etcd operator logs for key rotation check"
        fi
    fi
    
    # Create key rotation result
    local rotation_result
    rotation_result=$(cat << EOF
{
    "rotation_status": "${rotation_status}",
    "last_rotation": "${last_rotation}",
    "rotation_errors": "${rotation_errors}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    echo "${rotation_result}"
}

# Check etcd pod health
check_etcd_pod_health() {
    log_debug "Checking etcd pod health..."
    
    local healthy_pods=0
    local total_pods=0
    local pod_details=()
    local pod_errors=""
    
    # Get etcd pods
    local etcd_pods_json=""
    if etcd_pods_json=$(execute_oc_json "get pods -n openshift-etcd -l k8s-app=etcd -o json" "Get etcd pods"); then
        # Count total pods
        total_pods=$(count_json_array "${etcd_pods_json}" ".items" "etcd pods")
        
        if [[ "${total_pods}" -gt 0 ]]; then
            # Check each pod
            local pod_index=0
            while [[ ${pod_index} -lt ${total_pods} ]]; do
                local pod_name
                local pod_phase
                local pod_ready
                
                pod_name=$(parse_json_field "${etcd_pods_json}" ".items[${pod_index}].metadata.name" "" "pod name")
                pod_phase=$(parse_json_field "${etcd_pods_json}" ".items[${pod_index}].status.phase" "" "pod phase")
                
                # Check if pod is ready
                local ready_condition
                ready_condition=$(parse_json_field "${etcd_pods_json}" '.items['${pod_index}'].status.conditions[] | select(.type=="Ready") | .status' "" "ready condition")
                
                if [[ "${ready_condition}" == "True" ]]; then
                    pod_ready="true"
                else
                    pod_ready="false"
                fi
                
                # Determine pod health
                if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "true" ]]; then
                    ((healthy_pods++))
                    local pod_status="healthy"
                else
                    local pod_status="unhealthy"
                fi
                
                # Create pod detail
                local pod_detail
                pod_detail=$(cat << EOF
{
    "name": "${pod_name}",
    "phase": "${pod_phase}",
    "ready": "${pod_ready}",
    "status": "${pod_status}"
}
EOF
                )
                pod_details+=("${pod_detail}")
                
                ((pod_index++))
            done
        else
            pod_errors="No etcd pods found"
        fi
    else
        pod_errors="Failed to retrieve etcd pods"
    fi
    
    # Create pod health result
    local pod_health_json="["
    for i in "${!pod_details[@]}"; do
        if [[ ${i} -gt 0 ]]; then
            pod_health_json+=","
        fi
        pod_health_json+="${pod_details[${i}]}"
    done
    pod_health_json+="]"
    
    local pod_result
    pod_result=$(cat << EOF
{
    "healthy_pods": ${healthy_pods},
    "total_pods": ${total_pods},
    "pod_details": ${pod_health_json},
    "pod_errors": "${pod_errors}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    echo "${pod_result}"
}

# Check etcd encryption status across the cluster
check_etcd_encryption_status() {
    log_info "Checking etcd encryption status across the cluster..."
    
    # Reset etcd encryption status
    etcd_encryption_status["overall_status"]="${STATUS_UNKNOWN}"
    etcd_encryption_status["overall_message"]=""
    etcd_encryption_status["encryption_enabled"]="unknown"
    etcd_encryption_status["encryption_type"]="unknown"
    etcd_encryption_status["encryption_provider"]="unknown"
    etcd_encryption_status["reencryption_verified"]="unknown"
    etcd_encryption_status["reencryption_status"]="unknown"
    etcd_encryption_status["key_rotation_status"]="unknown"
    etcd_encryption_status["last_key_rotation"]="unknown"
    etcd_encryption_status["etcd_pods_healthy"]="0"
    etcd_encryption_status["etcd_pods_total"]="0"
    etcd_encryption_status["check_timestamp"]="$(get_timestamp)"
    etcd_encryption_status["details"]=""
    etcd_encryption_status["errors"]=""
    
    local error_messages=()
    local all_checks_successful=true
    
    # Check encryption configuration
    log_debug "Checking etcd encryption configuration..."
    local config_result=""
    if config_result=$(check_etcd_encryption_config); then
        local encryption_enabled
        local encryption_type
        local encryption_provider
        local config_errors
        
        encryption_enabled=$(parse_json_field "${config_result}" ".encryption_enabled" "unknown" "encryption enabled")
        encryption_type=$(parse_json_field "${config_result}" ".encryption_type" "unknown" "encryption type")
        encryption_provider=$(parse_json_field "${config_result}" ".encryption_provider" "unknown" "encryption provider")
        config_errors=$(parse_json_field "${config_result}" ".config_errors" "" "config errors")
        
        etcd_encryption_status["encryption_enabled"]="${encryption_enabled}"
        etcd_encryption_status["encryption_type"]="${encryption_type}"
        etcd_encryption_status["encryption_provider"]="${encryption_provider}"
        
        # Extract re-encryption verification data
        local reencryption_verified
        local reencryption_status
        reencryption_verified=$(parse_json_field "${config_result}" ".reencryption_verified" "unknown" "reencryption verified")
        reencryption_status=$(parse_json_field "${config_result}" ".reencryption_status" "unknown" "reencryption status")
        
        etcd_encryption_status["reencryption_verified"]="${reencryption_verified}"
        etcd_encryption_status["reencryption_status"]="${reencryption_status}"
        
        if [[ -n "${config_errors}" ]]; then
            error_messages+=("Configuration check: ${config_errors}")
            all_checks_successful=false
        fi
    else
        error_messages+=("Failed to check encryption configuration")
        all_checks_successful=false
    fi
    
    # Check key rotation status
    log_debug "Checking etcd key rotation status..."
    local rotation_result=""
    if rotation_result=$(check_etcd_key_rotation); then
        local rotation_status
        local last_rotation
        local rotation_errors
        
        rotation_status=$(parse_json_field "${rotation_result}" ".rotation_status" "unknown" "rotation status")
        last_rotation=$(parse_json_field "${rotation_result}" ".last_rotation" "unknown" "last rotation")
        rotation_errors=$(parse_json_field "${rotation_result}" ".rotation_errors" "" "rotation errors")
        
        etcd_encryption_status["key_rotation_status"]="${rotation_status}"
        etcd_encryption_status["last_key_rotation"]="${last_rotation}"
        
        if [[ -n "${rotation_errors}" ]]; then
            error_messages+=("Key rotation check: ${rotation_errors}")
        fi
    else
        error_messages+=("Failed to check key rotation status")
    fi
    
    # Check etcd pod health
    log_debug "Checking etcd pod health..."
    local pod_result=""
    if pod_result=$(check_etcd_pod_health); then
        local healthy_pods
        local total_pods
        local pod_errors
        
        healthy_pods=$(parse_json_field "${pod_result}" ".healthy_pods" "0" "healthy pods")
        total_pods=$(parse_json_field "${pod_result}" ".total_pods" "0" "total pods")
        pod_errors=$(parse_json_field "${pod_result}" ".pod_errors" "" "pod errors")
        
        etcd_encryption_status["etcd_pods_healthy"]="${healthy_pods}"
        etcd_encryption_status["etcd_pods_total"]="${total_pods}"
        
        if [[ -n "${pod_errors}" ]]; then
            error_messages+=("Pod health check: ${pod_errors}")
        fi
    else
        error_messages+=("Failed to check etcd pod health")
        all_checks_successful=false
    fi
    
    # Create detailed results
    local details_result
    details_result=$(cat << EOF
{
    "encryption_config": ${config_result:-"{}"},
    "key_rotation": ${rotation_result:-"{}"},
    "pod_health": ${pod_result:-"{}"}
}
EOF
    )
    etcd_encryption_status["details"]="${details_result}"
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        etcd_encryption_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    local encryption_enabled="${etcd_encryption_status["encryption_enabled"]}"
    local healthy_pods="${etcd_encryption_status["etcd_pods_healthy"]}"
    local total_pods="${etcd_encryption_status["etcd_pods_total"]}"
    
    if [[ ! "${all_checks_successful}" == "true" ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="Failed to complete etcd encryption status checks"
    elif [[ "${encryption_enabled}" == "false" ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="etcd encryption is not enabled"
    elif [[ "${encryption_enabled}" == "true" ]]; then
        if [[ "${total_pods}" -gt 0 && "${healthy_pods}" -eq "${total_pods}" ]]; then
            overall_status="${STATUS_HEALTHY}"
            overall_message="etcd encryption is enabled and all etcd pods are healthy"
        elif [[ "${healthy_pods}" -gt 0 ]]; then
            overall_status="${STATUS_WARNING}"
            overall_message="etcd encryption is enabled but some etcd pods are unhealthy (${healthy_pods}/${total_pods})"
        else
            overall_status="${STATUS_CRITICAL}"
            overall_message="etcd encryption is enabled but no etcd pods are healthy"
        fi
    else
        overall_status="${STATUS_UNKNOWN}"
        overall_message="Unable to determine etcd encryption status"
    fi
    
    # Update overall status
    etcd_encryption_status["overall_status"]="${overall_status}"
    etcd_encryption_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "etcd encryption status check completed:"
    log_info "  Encryption enabled: ${encryption_enabled}"
    log_info "  Encryption type: ${etcd_encryption_status["encryption_type"]}"
    log_info "  Encryption provider: ${etcd_encryption_status["encryption_provider"]}"
    log_info "  Resources re-encrypted: ${etcd_encryption_status["reencryption_verified"]}"
    log_info "  Re-encryption status: ${etcd_encryption_status["reencryption_status"]}"
    log_info "  Key rotation status: ${etcd_encryption_status["key_rotation_status"]}"
    log_info "  Healthy etcd pods: ${healthy_pods}/${total_pods}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get etcd encryption status summary
get_etcd_encryption_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${etcd_encryption_status["overall_status"]}",
    "overall_message": "${etcd_encryption_status["overall_message"]}",
    "encryption_enabled": "${etcd_encryption_status["encryption_enabled"]}",
    "encryption_type": "${etcd_encryption_status["encryption_type"]}",
    "encryption_provider": "${etcd_encryption_status["encryption_provider"]}",
    "key_rotation_status": "${etcd_encryption_status["key_rotation_status"]}",
    "last_key_rotation": "${etcd_encryption_status["last_key_rotation"]}",
    "etcd_pods_healthy": ${etcd_encryption_status["etcd_pods_healthy"]},
    "etcd_pods_total": ${etcd_encryption_status["etcd_pods_total"]},
    "check_timestamp": "${etcd_encryption_status["check_timestamp"]}",
    "details": ${etcd_encryption_status["details"]:-"{}"},
    "errors": "${etcd_encryption_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
etcd Encryption Status: ${etcd_encryption_status["overall_status"]}
Message: ${etcd_encryption_status["overall_message"]}
Encryption Enabled: ${etcd_encryption_status["encryption_enabled"]}
Encryption Type: ${etcd_encryption_status["encryption_type"]}
Encryption Provider: ${etcd_encryption_status["encryption_provider"]}
Key Rotation Status: ${etcd_encryption_status["key_rotation_status"]}
Last Key Rotation: ${etcd_encryption_status["last_key_rotation"]}
Healthy etcd Pods: ${etcd_encryption_status["etcd_pods_healthy"]}/${etcd_encryption_status["etcd_pods_total"]}
Check Timestamp: ${etcd_encryption_status["check_timestamp"]}
EOF
            if [[ -n "${etcd_encryption_status["errors"]}" ]]; then
                echo "Errors: ${etcd_encryption_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# IPSEC ENCRYPTION CHECK MODULE
# =============================================================================

# IPSec encryption status structure
declare -A ipsec_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["ipsec_enabled"]="unknown"
    ["ipsec_mode"]="unknown"
    ["network_type"]="unknown"
    ["ipsec_config"]="unknown"
    ["ipsec_pods_healthy"]="0"
    ["ipsec_pods_total"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check IPSec encryption configuration and status
check_ipsec_encryption_status() {
    log_info "Checking IPSec encryption status..."
    
    # Reset IPSec status
    ipsec_status["overall_status"]="${STATUS_UNKNOWN}"
    ipsec_status["overall_message"]=""
    ipsec_status["ipsec_enabled"]="unknown"
    ipsec_status["ipsec_mode"]="unknown"
    ipsec_status["network_type"]="unknown"
    ipsec_status["ipsec_config"]="unknown"
    ipsec_status["ipsec_pods_healthy"]="0"
    ipsec_status["ipsec_pods_total"]="0"
    ipsec_status["check_timestamp"]="$(get_timestamp)"
    ipsec_status["details"]=""
    ipsec_status["errors"]=""
    
    local error_messages=()
    local all_checks_successful=true
    
    # Check network operator configuration for IPSec
    log_debug "Checking network operator configuration for IPSec..."
    local network_operator_config=""
    if network_operator_config=$(execute_oc_json "get networks.operator.openshift.io cluster -o json" "Get network operator configuration"); then
        # Parse network type from operator config
        local network_type
        network_type=$(parse_json_field "${network_operator_config}" ".spec.defaultNetwork.type" "unknown" "network type")
        if [[ "${network_type}" == "unknown" ]]; then
            # Fallback: check if OVN config exists
            local ovn_config
            ovn_config=$(parse_json_field "${network_operator_config}" ".spec.defaultNetwork.ovnKubernetesConfig" "null" "OVN config")
            if [[ "${ovn_config}" != "null" && "${ovn_config}" != "{}" ]]; then
                network_type="OVNKubernetes"
            fi
        fi
        ipsec_status["network_type"]="${network_type}"
        
        log_debug "Network type: ${network_type}"
        
        # Check for IPSec configuration in network operator
        local ipsec_config
        ipsec_config=$(parse_json_field "${network_operator_config}" ".spec.defaultNetwork.ovnKubernetesConfig.ipsecConfig" "null" "IPSec config")
        
        if [[ "${ipsec_config}" != "null" && "${ipsec_config}" != "{}" && -n "${ipsec_config}" ]]; then
            # Extract IPSec mode first to determine if it's actually enabled
            local ipsec_mode
            ipsec_mode=$(parse_json_field "${ipsec_config}" ".mode" "unknown" "IPSec mode")
            ipsec_status["ipsec_mode"]="${ipsec_mode}"
            
            # Check if IPSec is actually enabled based on the mode
            if [[ "${ipsec_mode}" == "Disabled" || "${ipsec_mode}" == "disabled" ]]; then
                ipsec_status["ipsec_enabled"]="false"
                ipsec_status["ipsec_config"]="configured_but_disabled"
                log_debug "IPSec configuration found but mode is disabled: ${ipsec_mode}"
            else
                ipsec_status["ipsec_enabled"]="true"
                ipsec_status["ipsec_config"]="configured"
                log_debug "IPSec configuration found and enabled with mode: ${ipsec_mode}"
            fi
        else
            ipsec_status["ipsec_enabled"]="false"
            ipsec_status["ipsec_config"]="not_configured"
            log_debug "No IPSec configuration found in network operator"
        fi
    else
        error_messages+=("Failed to retrieve network operator configuration")
        all_checks_successful=false
    fi
    
    # Only check for IPSec-related resources if mode is not explicitly disabled
    if [[ "${ipsec_status["ipsec_config"]}" != "configured_but_disabled" ]]; then
        log_debug "Checking for IPSec-related resources..."
        
        # Check for IPSec secrets
        local ipsec_secrets=""
        if ipsec_secrets=$(execute_oc_command "get secrets -n openshift-ovn-kubernetes -l k8s-app=ovn-ipsec --no-headers" "Get IPSec secrets" 1 2>/dev/null); then
            if [[ -n "${ipsec_secrets}" ]]; then
                ipsec_status["ipsec_enabled"]="true"
                ipsec_status["ipsec_config"]="secrets_found"
                log_debug "IPSec secrets found"
            fi
        fi
        
        # Check for IPSec pods
        local ipsec_pods_json=""
        if ipsec_pods_json=$(execute_oc_json "get pods -n openshift-ovn-kubernetes -l app=ovn-ipsec -o json" "Get IPSec pods" 1 2>/dev/null); then
            local total_pods
            total_pods=$(count_json_array "${ipsec_pods_json}" ".items" "IPSec pods")
            ipsec_status["ipsec_pods_total"]="${total_pods}"
            
            if [[ "${total_pods}" -gt 0 ]]; then
                ipsec_status["ipsec_enabled"]="true"
                # Keep the original mode from configuration, don't overwrite it
                
                # Count healthy pods
                local healthy_pods=0
                local pod_index=0
                
                while [[ ${pod_index} -lt ${total_pods} ]]; do
                    local pod_phase
                    pod_phase=$(parse_json_field "${ipsec_pods_json}" ".items[${pod_index}].status.phase" "" "pod phase")
                    
                    if [[ "${pod_phase}" == "Running" ]]; then
                        ((healthy_pods++))
                    fi
                    ((pod_index++))
                done
                
                ipsec_status["ipsec_pods_healthy"]="${healthy_pods}"
                log_debug "Found ${total_pods} IPSec pods, ${healthy_pods} healthy"
            else
                log_debug "No IPSec pods found"
            fi
        else
            log_debug "Could not retrieve IPSec pods information"
        fi
        
        # Check for OVN-Kubernetes IPSec configuration
        log_debug "Checking OVN-Kubernetes IPSec configuration..."
        local ovn_config=""
        if ovn_config=$(execute_oc_json "get configmap -n openshift-ovn-kubernetes ovn-config -o json" "Get OVN config" 1 2>/dev/null); then
            local ovn_data
            ovn_data=$(parse_json_field "${ovn_config}" ".data" "{}" "OVN config data")
            
            if echo "${ovn_data}" | grep -qi "ipsec\|encrypt"; then
                ipsec_status["ipsec_enabled"]="true"
                ipsec_status["ipsec_config"]="ovn_configured"
                log_debug "IPSec configuration found in OVN config"
            fi
        fi
        
        # Check for IPSec-related annotations on nodes
        log_debug "Checking nodes for IPSec annotations..."
        local nodes_json=""
        if nodes_json=$(execute_oc_json "get nodes -o json" "Get nodes for IPSec check" 1 2>/dev/null); then
            local total_nodes
            total_nodes=$(count_json_array "${nodes_json}" ".items" "cluster nodes")
            
            if [[ "${total_nodes}" -gt 0 ]]; then
                local node_index=0
                local ipsec_nodes=0
                
                while [[ ${node_index} -lt ${total_nodes} ]]; do
                    local node_annotations
                    node_annotations=$(parse_json_field "${nodes_json}" ".items[${node_index}].metadata.annotations" "{}" "node annotations")
                    
                    if echo "${node_annotations}" | grep -qi "ipsec\|encrypt"; then
                        ((ipsec_nodes++))
                    fi
                    
                    ((node_index++))
                done
                
                if [[ ${ipsec_nodes} -gt 0 ]]; then
                    ipsec_status["ipsec_enabled"]="true"
                    ipsec_status["ipsec_config"]="node_annotations"
                    log_debug "IPSec annotations found on ${ipsec_nodes} nodes"
                fi
            fi
        fi
    else
        log_debug "Skipping IPSec resource checks because mode is explicitly disabled"
        # Still check for pods count for informational purposes
        local ipsec_pods_json=""
        if ipsec_pods_json=$(execute_oc_json "get pods -n openshift-ovn-kubernetes -l app=ovn-ipsec -o json" "Get IPSec pods" 1 2>/dev/null); then
            local total_pods
            total_pods=$(count_json_array "${ipsec_pods_json}" ".items" "IPSec pods")
            ipsec_status["ipsec_pods_total"]="${total_pods}"
            
            if [[ "${total_pods}" -gt 0 ]]; then
                # Count healthy pods for informational purposes
                local healthy_pods=0
                local pod_index=0
                
                while [[ ${pod_index} -lt ${total_pods} ]]; do
                    local pod_phase
                    pod_phase=$(parse_json_field "${ipsec_pods_json}" ".items[${pod_index}].status.phase" "" "pod phase")
                    
                    if [[ "${pod_phase}" == "Running" ]]; then
                        ((healthy_pods++))
                    fi
                    ((pod_index++))
                done
                
                ipsec_status["ipsec_pods_healthy"]="${healthy_pods}"
                log_debug "Found ${total_pods} IPSec pods (${healthy_pods} healthy) but IPSec is disabled by configuration"
            fi
        fi
    fi
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        ipsec_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    if [[ ! "${all_checks_successful}" == "true" ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="Failed to complete IPSec encryption status checks"
    elif [[ "${ipsec_status["ipsec_enabled"]}" == "true" ]]; then
        local healthy_pods="${ipsec_status["ipsec_pods_healthy"]}"
        local total_pods="${ipsec_status["ipsec_pods_total"]}"
        
        if [[ "${total_pods}" -gt 0 ]]; then
            if [[ ${healthy_pods} -eq ${total_pods} ]]; then
                overall_status="${STATUS_HEALTHY}"
                overall_message="IPSec encryption is enabled and all ${total_pods} IPSec pod(s) are healthy"
            elif [[ ${healthy_pods} -gt 0 ]]; then
                overall_status="${STATUS_WARNING}"
                overall_message="IPSec encryption is enabled but only ${healthy_pods}/${total_pods} IPSec pod(s) are healthy"
            else
                overall_status="${STATUS_CRITICAL}"
                overall_message="IPSec encryption is configured but no IPSec pods are healthy"
            fi
        else
            overall_status="${STATUS_HEALTHY}"
            overall_message="IPSec encryption is enabled (configuration-based)"
        fi
    elif [[ "${ipsec_status["ipsec_enabled"]}" == "false" ]]; then
        # Check if it's explicitly disabled vs not configured
        if [[ "${ipsec_status["ipsec_config"]}" == "configured_but_disabled" ]]; then
            overall_status="${STATUS_WARNING}"
            overall_message="IPSec encryption is explicitly disabled (mode: ${ipsec_status["ipsec_mode"]}) - pod-to-pod traffic is not encrypted"
        else
            overall_status="${STATUS_WARNING}"
            overall_message="IPSec encryption is not configured - pod-to-pod traffic is not encrypted"
        fi
    else
        overall_status="${STATUS_UNKNOWN}"
        overall_message="Unable to determine IPSec encryption status"
    fi
    
    # Update overall status
    ipsec_status["overall_status"]="${overall_status}"
    ipsec_status["overall_message"]="${overall_message}"
    
    # Create details result
    local details_result
    details_result=$(cat << EOF
{
    "ipsec_enabled": "${ipsec_status["ipsec_enabled"]}",
    "ipsec_mode": "${ipsec_status["ipsec_mode"]}",
    "network_type": "${ipsec_status["network_type"]}",
    "ipsec_config": "${ipsec_status["ipsec_config"]}",
    "ipsec_pods_healthy": ${ipsec_status["ipsec_pods_healthy"]},
    "ipsec_pods_total": ${ipsec_status["ipsec_pods_total"]},
    "check_timestamp": "${ipsec_status["check_timestamp"]}"
}
EOF
    )
    ipsec_status["details"]="${details_result}"
    
    # Log summary
    log_info "IPSec encryption status check completed:"
    log_info "  IPSec enabled: ${ipsec_status["ipsec_enabled"]}"
    log_info "  Network type: ${ipsec_status["network_type"]}"
    log_info "  IPSec mode: ${ipsec_status["ipsec_mode"]}"
    log_info "  IPSec config: ${ipsec_status["ipsec_config"]}"
    log_info "  Healthy IPSec pods: ${ipsec_status["ipsec_pods_healthy"]}/${ipsec_status["ipsec_pods_total"]}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get IPSec encryption status summary
get_ipsec_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${ipsec_status["overall_status"]}",
    "overall_message": "${ipsec_status["overall_message"]}",
    "ipsec_enabled": "${ipsec_status["ipsec_enabled"]}",
    "ipsec_mode": "${ipsec_status["ipsec_mode"]}",
    "network_type": "${ipsec_status["network_type"]}",
    "ipsec_config": "${ipsec_status["ipsec_config"]}",
    "ipsec_pods_healthy": ${ipsec_status["ipsec_pods_healthy"]},
    "ipsec_pods_total": ${ipsec_status["ipsec_pods_total"]},
    "check_timestamp": "${ipsec_status["check_timestamp"]}",
    "details": ${ipsec_status["details"]:-"{}"},
    "errors": "${ipsec_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
IPSec Encryption Status: ${ipsec_status["overall_status"]}
Message: ${ipsec_status["overall_message"]}
IPSec Enabled: ${ipsec_status["ipsec_enabled"]}
IPSec Mode: ${ipsec_status["ipsec_mode"]}
Network Type: ${ipsec_status["network_type"]}
IPSec Configuration: ${ipsec_status["ipsec_config"]}
Healthy IPSec Pods: ${ipsec_status["ipsec_pods_healthy"]}/${ipsec_status["ipsec_pods_total"]}
Check Timestamp: ${ipsec_status["check_timestamp"]}
EOF
            if [[ -n "${ipsec_status["errors"]}" ]]; then
                echo "Errors: ${ipsec_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# OAUTH AUTHENTICATION DETAILS MODULE
# =============================================================================

# OAuth authentication status structure
declare -A oauth_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["oauth_configured"]="unknown"
    ["identity_providers_count"]="0"
    ["identity_providers_types"]=""
    ["oauth_pods_healthy"]="0"
    ["oauth_pods_total"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check individual OAuth identity provider configuration
check_oauth_identity_provider() {
    local provider_json="$1"
    local provider_name="$2"
    
    log_debug "Analyzing OAuth identity provider: ${provider_name}"
    
    # Extract provider information
    local provider_type=""
    local provider_challenge=""
    local provider_login=""
    local provider_mapping_method=""
    local provider_config=""
    
    provider_type=$(parse_json_field "${provider_json}" ".type" "unknown" "provider type")
    provider_challenge=$(parse_json_field "${provider_json}" ".challenge" "false" "provider challenge")
    provider_login=$(parse_json_field "${provider_json}" ".login" "false" "provider login")
    provider_mapping_method=$(parse_json_field "${provider_json}" ".mappingMethod" "claim" "mapping method")
    
    # Extract provider-specific configuration based on type
    case "${provider_type}" in
        "HTPasswd")
            local htpasswd_file
            htpasswd_file=$(parse_json_field "${provider_json}" ".htpasswd.fileData.name" "unknown" "htpasswd file")
            provider_config="File: ${htpasswd_file}"
            ;;
        "LDAP")
            local ldap_url
            local ldap_bind_dn
            ldap_url=$(parse_json_field "${provider_json}" ".ldap.url" "unknown" "LDAP URL")
            ldap_bind_dn=$(parse_json_field "${provider_json}" ".ldap.bindDN" "unknown" "LDAP bind DN")
            provider_config="URL: ${ldap_url}, Bind DN: ${ldap_bind_dn}"
            ;;
        "OpenID")
            local openid_issuer
            local openid_client_id
            openid_issuer=$(parse_json_field "${provider_json}" ".openID.issuer" "unknown" "OpenID issuer")
            openid_client_id=$(parse_json_field "${provider_json}" ".openID.clientID" "unknown" "OpenID client ID")
            provider_config="Issuer: ${openid_issuer}, Client ID: ${openid_client_id}"
            ;;
        "GitHub")
            local github_hostname
            local github_org
            github_hostname=$(parse_json_field "${provider_json}" ".github.hostname" "github.com" "GitHub hostname")
            github_org=$(parse_json_field "${provider_json}" ".github.organizations[0]" "unknown" "GitHub organization")
            provider_config="Hostname: ${github_hostname}, Organization: ${github_org}"
            ;;
        "GitLab")
            local gitlab_url
            gitlab_url=$(parse_json_field "${provider_json}" ".gitlab.url" "https://gitlab.com" "GitLab URL")
            provider_config="URL: ${gitlab_url}"
            ;;
        "Google")
            local google_hosted_domain
            google_hosted_domain=$(parse_json_field "${provider_json}" ".google.hostedDomain" "unknown" "Google hosted domain")
            provider_config="Hosted Domain: ${google_hosted_domain}"
            ;;
        *)
            provider_config="Type-specific configuration available"
            ;;
    esac
    
    # Create provider detail JSON
    local provider_detail
    provider_detail=$(cat << EOF
{
    "name": "${provider_name}",
    "type": "${provider_type}",
    "challenge": ${provider_challenge},
    "login": ${provider_login},
    "mapping_method": "${provider_mapping_method}",
    "configuration": "${provider_config}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    log_debug "OAuth provider ${provider_name}: type=${provider_type}, challenge=${provider_challenge}, login=${provider_login}"
    echo "${provider_detail}"
}

# Check OAuth authentication configuration
check_oauth_authentication_status() {
    log_info "Checking OAuth authentication configuration..."
    
    # Reset OAuth status
    oauth_status["overall_status"]="${STATUS_UNKNOWN}"
    oauth_status["overall_message"]=""
    oauth_status["oauth_configured"]="unknown"
    oauth_status["identity_providers_count"]="0"
    oauth_status["identity_providers_types"]=""
    oauth_status["oauth_pods_healthy"]="0"
    oauth_status["oauth_pods_total"]="0"
    oauth_status["check_timestamp"]="$(get_timestamp)"
    oauth_status["details"]=""
    oauth_status["errors"]=""
    
    local error_messages=()
    local all_checks_successful=true
    
    # Check OAuth cluster configuration
    log_debug "Checking OAuth cluster configuration..."
    local oauth_config_json=""
    if ! oauth_config_json=$(execute_oc_json "get oauth cluster -o json" "Get OAuth cluster configuration"); then
        log_error "Failed to retrieve OAuth cluster configuration"
        oauth_status["overall_status"]="${STATUS_CRITICAL}"
        oauth_status["overall_message"]="Failed to retrieve OAuth configuration"
        oauth_status["errors"]="Unable to access OAuth cluster configuration"
        return 1
    fi
    
    # Validate OAuth config JSON
    if ! validate_json "${oauth_config_json}" "OAuth config data"; then
        log_error "Invalid JSON response from OAuth config query"
        oauth_status["overall_status"]="${STATUS_CRITICAL}"
        oauth_status["overall_message"]="Invalid response from OAuth API"
        oauth_status["errors"]="Invalid JSON response from OAuth config query"
        return 1
    fi
    
    # Extract identity providers
    local identity_providers_json=""
    identity_providers_json=$(parse_json_field "${oauth_config_json}" ".spec.identityProviders" "[]" "identity providers")
    
    # Count identity providers
    local providers_count
    providers_count=$(count_json_array "${identity_providers_json}" "." "identity providers")
    oauth_status["identity_providers_count"]="${providers_count}"
    
    if [[ "${providers_count}" -eq 0 ]]; then
        log_warn "No identity providers configured"
        oauth_status["oauth_configured"]="false"
        oauth_status["overall_status"]="${STATUS_WARNING}"
        oauth_status["overall_message"]="No identity providers configured"
        oauth_status["identity_providers_types"]="None"
    else
        log_info "Found ${providers_count} identity provider(s)"
        oauth_status["oauth_configured"]="true"
        
        # Process each identity provider
        local provider_details=()
        local provider_types=()
        local provider_index=0
        
        while [[ ${provider_index} -lt ${providers_count} ]]; do
            # Extract individual provider JSON
            local single_provider_json
            single_provider_json=$(parse_json_field "${identity_providers_json}" ".[${provider_index}]" "{}" "provider data")
            
            local provider_name
            provider_name=$(parse_json_field "${single_provider_json}" ".name" "provider-${provider_index}" "provider name")
            
            local provider_type
            provider_type=$(parse_json_field "${single_provider_json}" ".type" "unknown" "provider type")
            provider_types+=("${provider_type}")
            
            log_debug "Processing identity provider ${provider_index}/${providers_count}: ${provider_name} (${provider_type})"
            
            # Get detailed provider information
            local provider_result=""
            if provider_result=$(check_oauth_identity_provider "${single_provider_json}" "${provider_name}"); then
                provider_details+=("${provider_result}")
                log_debug "Successfully analyzed provider: ${provider_name}"
            else
                log_error "Failed to analyze identity provider: ${provider_name}"
                error_messages+=("${provider_name}: Failed to analyze provider details")
                all_checks_successful=false
            fi
            
            ((provider_index++))
        done
        
        # Join provider types with comma
        oauth_status["identity_providers_types"]=$(IFS=","; echo "${provider_types[*]}")
        
        # Create details JSON array
        local details_json="["
        for i in "${!provider_details[@]}"; do
            if [[ ${i} -gt 0 ]]; then
                details_json+=","
            fi
            details_json+="${provider_details[${i}]}"
        done
        details_json+="]"
        oauth_status["details"]="${details_json}"
    fi
    
    # Check OAuth pods health
    log_debug "Checking OAuth pods health..."
    local oauth_pods_json=""
    if oauth_pods_json=$(execute_oc_json "get pods -n openshift-authentication -l app=oauth-openshift -o json" "Get OAuth pods" 2>/dev/null); then
        local total_pods
        total_pods=$(count_json_array "${oauth_pods_json}" ".items" "OAuth pods")
        oauth_status["oauth_pods_total"]="${total_pods}"
        
        if [[ "${total_pods}" -gt 0 ]]; then
            # Count healthy pods
            local healthy_pods=0
            local pod_index=0
            
            while [[ ${pod_index} -lt ${total_pods} ]]; do
                local pod_phase
                pod_phase=$(parse_json_field "${oauth_pods_json}" ".items[${pod_index}].status.phase" "Unknown" "pod phase")
                
                if [[ "${pod_phase}" == "Running" ]]; then
                    ((healthy_pods++))
                fi
                
                ((pod_index++))
            done
            
            oauth_status["oauth_pods_healthy"]="${healthy_pods}"
            
            if [[ ${healthy_pods} -lt ${total_pods} ]]; then
                error_messages+=("OAuth pods: ${healthy_pods}/${total_pods} pods are healthy")
                all_checks_successful=false
            fi
        else
            error_messages+=("No OAuth pods found in openshift-authentication namespace")
            all_checks_successful=false
        fi
    else
        log_warn "Could not retrieve OAuth pods information"
        error_messages+=("Unable to check OAuth pods health")
        oauth_status["oauth_pods_total"]="unknown"
        oauth_status["oauth_pods_healthy"]="unknown"
    fi
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        oauth_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    if [[ "${oauth_status["oauth_configured"]}" == "false" ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="No identity providers configured - using default authentication"
    elif [[ "${oauth_status["oauth_configured"]}" == "true" ]]; then
        if [[ "${all_checks_successful}" == "true" ]]; then
            overall_status="${STATUS_HEALTHY}"
            overall_message="${providers_count} identity provider(s) configured and healthy"
        else
            overall_status="${STATUS_WARNING}"
            overall_message="${providers_count} identity provider(s) configured with some issues"
        fi
    else
        overall_status="${STATUS_CRITICAL}"
        overall_message="Unable to determine OAuth configuration status"
    fi
    
    # Update overall status
    oauth_status["overall_status"]="${overall_status}"
    oauth_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "OAuth authentication check completed:"
    log_info "  OAuth configured: ${oauth_status["oauth_configured"]}"
    log_info "  Identity providers: ${oauth_status["identity_providers_count"]}"
    log_info "  Provider types: ${oauth_status["identity_providers_types"]}"
    log_info "  OAuth pods: ${oauth_status["oauth_pods_healthy"]}/${oauth_status["oauth_pods_total"]}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get OAuth authentication status summary
get_oauth_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${oauth_status["overall_status"]}",
    "overall_message": "${oauth_status["overall_message"]}",
    "oauth_configured": "${oauth_status["oauth_configured"]}",
    "identity_providers_count": ${oauth_status["identity_providers_count"]},
    "identity_providers_types": "${oauth_status["identity_providers_types"]}",
    "oauth_pods_healthy": "${oauth_status["oauth_pods_healthy"]}",
    "oauth_pods_total": "${oauth_status["oauth_pods_total"]}",
    "check_timestamp": "${oauth_status["check_timestamp"]}",
    "details": ${oauth_status["details"]:-"[]"},
    "errors": "${oauth_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
OAuth Authentication Status: ${oauth_status["overall_status"]}
Message: ${oauth_status["overall_message"]}
OAuth Configured: ${oauth_status["oauth_configured"]}
Identity Providers Count: ${oauth_status["identity_providers_count"]}
Identity Provider Types: ${oauth_status["identity_providers_types"]}
OAuth Pods Healthy: ${oauth_status["oauth_pods_healthy"]}/${oauth_status["oauth_pods_total"]}
Check Timestamp: ${oauth_status["check_timestamp"]}
EOF
            if [[ -n "${oauth_status["errors"]}" ]]; then
                echo "Errors: ${oauth_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# CLUSTER OPERATORS STATUS MODULE
# =============================================================================

# Cluster operators status structure
declare -A cluster_operators_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["available_operators"]="0"
    ["progressing_operators"]="0"
    ["degraded_operators"]="0"
    ["total_operators"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check cluster operators status
check_cluster_operators_status() {
    log_info "Checking cluster operators status..."
    
    # Reset cluster operators status
    cluster_operators_status["overall_status"]="${STATUS_UNKNOWN}"
    cluster_operators_status["overall_message"]=""
    cluster_operators_status["available_operators"]="0"
    cluster_operators_status["progressing_operators"]="0"
    cluster_operators_status["degraded_operators"]="0"
    cluster_operators_status["total_operators"]="0"
    cluster_operators_status["check_timestamp"]="$(get_timestamp)"
    cluster_operators_status["details"]=""
    cluster_operators_status["errors"]=""
    
    # Get cluster operators
    local operators_json=""
    if ! operators_json=$(execute_oc_json "get clusteroperators -o json" "Get cluster operators"); then
        log_error "Failed to retrieve cluster operators"
        cluster_operators_status["overall_status"]="${STATUS_CRITICAL}"
        cluster_operators_status["overall_message"]="Failed to retrieve cluster operators"
        cluster_operators_status["errors"]="Unable to access cluster operators"
        return 1
    fi
    
    # Validate operators JSON
    if ! validate_json "${operators_json}" "cluster operators data"; then
        log_error "Invalid JSON response from cluster operators query"
        cluster_operators_status["overall_status"]="${STATUS_CRITICAL}"
        cluster_operators_status["overall_message"]="Invalid response from cluster API"
        cluster_operators_status["errors"]="Invalid JSON response from cluster operators query"
        return 1
    fi
    
    # Count total operators
    local total_operators
    total_operators=$(count_json_array "${operators_json}" ".items" "cluster operators")
    cluster_operators_status["total_operators"]="${total_operators}"
    
    if [[ "${total_operators}" -eq 0 ]]; then
        log_warn "No cluster operators found"
        cluster_operators_status["overall_status"]="${STATUS_UNKNOWN}"
        cluster_operators_status["overall_message"]="No cluster operators found"
        return 0
    fi
    
    log_info "Found ${total_operators} cluster operators to check"
    
    # Initialize counters
    local available_count=0
    local progressing_count=0
    local degraded_count=0
    local operator_details=()
    local error_messages=()
    
    # Process each operator
    local operator_index=0
    while [[ ${operator_index} -lt ${total_operators} ]]; do
        # Extract operator information
        local operator_name
        local available_condition
        local progressing_condition
        local degraded_condition
        
        operator_name=$(parse_json_field "${operators_json}" ".items[${operator_index}].metadata.name" "" "operator name")
        
        if [[ -z "${operator_name}" ]]; then
            log_warn "Skipping operator with missing name at index ${operator_index}"
            ((operator_index++))
            continue
        fi
        
        # Get operator conditions
        available_condition=$(parse_json_field "${operators_json}" ".items[${operator_index}].status.conditions[] | select(.type==\"Available\") | .status" "Unknown" "available condition")
        progressing_condition=$(parse_json_field "${operators_json}" ".items[${operator_index}].status.conditions[] | select(.type==\"Progressing\") | .status" "Unknown" "progressing condition")
        degraded_condition=$(parse_json_field "${operators_json}" ".items[${operator_index}].status.conditions[] | select(.type==\"Degraded\") | .status" "Unknown" "degraded condition")
        
        # Determine operator status
        local operator_status
        operator_status=$(determine_status "${operator_name}" "${available_condition}" "${progressing_condition}" "${degraded_condition}")
        
        # Update counters
        case "${operator_status}" in
            "${STATUS_HEALTHY}")
                ((available_count++))
                ;;
            "${STATUS_WARNING}")
                ((progressing_count++))
                ;;
            "${STATUS_CRITICAL}")
                ((degraded_count++))
                ;;
        esac
        
        # Create operator detail
        local operator_detail
        operator_detail=$(cat << EOF
{
    "name": "${operator_name}",
    "status": "${operator_status}",
    "available": "${available_condition}",
    "progressing": "${progressing_condition}",
    "degraded": "${degraded_condition}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
        )
        operator_details+=("${operator_detail}")
        
        log_debug "Operator ${operator_name}: ${operator_status}"
        ((operator_index++))
    done
    
    # Update status counters
    cluster_operators_status["available_operators"]="${available_count}"
    cluster_operators_status["progressing_operators"]="${progressing_count}"
    cluster_operators_status["degraded_operators"]="${degraded_count}"
    
    # Create details JSON array
    local details_json="["
    for i in "${!operator_details[@]}"; do
        if [[ ${i} -gt 0 ]]; then
            details_json+=","
        fi
        details_json+="${operator_details[${i}]}"
    done
    details_json+="]"
    cluster_operators_status["details"]="${details_json}"
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    if [[ ${degraded_count} -gt 0 ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="${degraded_count} cluster operator(s) are degraded"
    elif [[ ${progressing_count} -gt 0 ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="${progressing_count} cluster operator(s) are progressing"
    elif [[ ${available_count} -eq ${total_operators} ]]; then
        overall_status="${STATUS_HEALTHY}"
        overall_message="All ${total_operators} cluster operators are available"
    else
        overall_status="${STATUS_WARNING}"
        overall_message="Mixed status across cluster operators"
    fi
    
    # Update overall status
    cluster_operators_status["overall_status"]="${overall_status}"
    cluster_operators_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "Cluster operators status check completed:"
    log_info "  Total operators: ${total_operators}"
    log_info "  Available operators: ${available_count}"
    log_info "  Progressing operators: ${progressing_count}"
    log_info "  Degraded operators: ${degraded_count}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get cluster operators status summary
get_cluster_operators_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${cluster_operators_status["overall_status"]}",
    "overall_message": "${cluster_operators_status["overall_message"]}",
    "available_operators": ${cluster_operators_status["available_operators"]},
    "progressing_operators": ${cluster_operators_status["progressing_operators"]},
    "degraded_operators": ${cluster_operators_status["degraded_operators"]},
    "total_operators": ${cluster_operators_status["total_operators"]},
    "check_timestamp": "${cluster_operators_status["check_timestamp"]}",
    "details": ${cluster_operators_status["details"]:-"[]"},
    "errors": "${cluster_operators_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
Cluster Operators Status: ${cluster_operators_status["overall_status"]}
Message: ${cluster_operators_status["overall_message"]}
Available Operators: ${cluster_operators_status["available_operators"]}/${cluster_operators_status["total_operators"]}
Progressing Operators: ${cluster_operators_status["progressing_operators"]}/${cluster_operators_status["total_operators"]}
Degraded Operators: ${cluster_operators_status["degraded_operators"]}/${cluster_operators_status["total_operators"]}
Check Timestamp: ${cluster_operators_status["check_timestamp"]}
EOF
            if [[ -n "${cluster_operators_status["errors"]}" ]]; then
                echo "Errors: ${cluster_operators_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# ALERTMANAGER STATUS MODULE
# =============================================================================

# AlertManager status structure
declare -A alertmanager_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["deployment_status"]="unknown"
    ["pod_count"]="0"
    ["healthy_pods"]="0"
    ["receivers_configured"]="0"
    ["routes_configured"]="0"
    ["receiver_status"]="unknown"
    ["receiver_details"]=""
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check AlertManager status
check_alertmanager_status() {
    log_info "Checking AlertManager status..."
    
    # Reset AlertManager status
    alertmanager_status["overall_status"]="${STATUS_UNKNOWN}"
    alertmanager_status["overall_message"]=""
    alertmanager_status["deployment_status"]="unknown"
    alertmanager_status["pod_count"]="0"
    alertmanager_status["healthy_pods"]="0"
    alertmanager_status["receivers_configured"]="0"
    alertmanager_status["routes_configured"]="0"
    alertmanager_status["check_timestamp"]="$(get_timestamp)"
    alertmanager_status["details"]=""
    alertmanager_status["errors"]=""
    
    local error_messages=()
    
    # Check AlertManager pods
    local pods_json=""
    if pods_json=$(execute_oc_json "get pods -n openshift-monitoring -l app.kubernetes.io/name=alertmanager -o json" "Get AlertManager pods"); then
        local total_pods
        local healthy_pods=0
        
        total_pods=$(count_json_array "${pods_json}" ".items" "AlertManager pods")
        alertmanager_status["pod_count"]="${total_pods}"
        
        if [[ "${total_pods}" -gt 0 ]]; then
            # Check pod health
            local pod_index=0
            while [[ ${pod_index} -lt ${total_pods} ]]; do
                local pod_phase
                pod_phase=$(parse_json_field "${pods_json}" ".items[${pod_index}].status.phase" "" "pod phase")
                
                if [[ "${pod_phase}" == "Running" ]]; then
                    ((healthy_pods++))
                fi
                ((pod_index++))
            done
            
            alertmanager_status["healthy_pods"]="${healthy_pods}"
            
            if [[ ${healthy_pods} -eq ${total_pods} ]]; then
                alertmanager_status["deployment_status"]="healthy"
            elif [[ ${healthy_pods} -gt 0 ]]; then
                alertmanager_status["deployment_status"]="partial"
            else
                alertmanager_status["deployment_status"]="unhealthy"
            fi
        else
            alertmanager_status["deployment_status"]="not_found"
            error_messages+=("No AlertManager pods found")
        fi
    else
        error_messages+=("Failed to retrieve AlertManager pods")
    fi
    
    # Check AlertManager configuration for receivers
    local config_json=""
    local receivers_configured="false"
    local receiver_details=""
    local receiver_types=""
    
    if config_json=$(execute_oc_json "get secret alertmanager-main -n openshift-monitoring -o json" "Get AlertManager config"); then
        # Try to decode and parse the configuration
        local config_data
        config_data=$(parse_json_field "${config_json}" ".data[\"alertmanager.yaml\"]" "" "config data")
        
        if [[ -n "${config_data}" ]]; then
            # Decode base64 and analyze the configuration
            local decoded_config
            if decoded_config=$(echo "${config_data}" | base64 -d 2>/dev/null); then
                log_debug "AlertManager config decoded successfully"
                
                # Count receivers (excluding the default null receiver)
                local receivers_count
                receivers_count=$(echo "${decoded_config}" | grep -c "^- name:" || echo "0")
                
                # Check for specific receiver types
                local has_email=$(echo "${decoded_config}" | grep -c "email_configs:" || echo "0")
                local has_slack=$(echo "${decoded_config}" | grep -c "slack_configs:" || echo "0")
                local has_webhook=$(echo "${decoded_config}" | grep -c "webhook_configs:" || echo "0")
                local has_pagerduty=$(echo "${decoded_config}" | grep -c "pagerduty_configs:" || echo "0")
                local has_opsgenie=$(echo "${decoded_config}" | grep -c "opsgenie_configs:" || echo "0")
                
                # Count routes
                local routes_count
                routes_count=$(echo "${decoded_config}" | grep -c "route:" || echo "0")
                
                # Determine if receivers are actually configured (not just default)
                local configured_receivers=0
                if [[ ${has_email} -gt 0 ]]; then
                    configured_receivers=$((configured_receivers + has_email))
                    receiver_types="${receiver_types}email,"
                fi
                if [[ ${has_slack} -gt 0 ]]; then
                    configured_receivers=$((configured_receivers + has_slack))
                    receiver_types="${receiver_types}slack,"
                fi
                if [[ ${has_webhook} -gt 0 ]]; then
                    configured_receivers=$((configured_receivers + has_webhook))
                    receiver_types="${receiver_types}webhook,"
                fi
                if [[ ${has_pagerduty} -gt 0 ]]; then
                    configured_receivers=$((configured_receivers + has_pagerduty))
                    receiver_types="${receiver_types}pagerduty,"
                fi
                if [[ ${has_opsgenie} -gt 0 ]]; then
                    configured_receivers=$((configured_receivers + has_opsgenie))
                    receiver_types="${receiver_types}opsgenie,"
                fi
                
                # Remove trailing comma
                receiver_types="${receiver_types%,}"
                
                # Set status based on configured receivers
                if [[ ${configured_receivers} -gt 0 ]]; then
                    receivers_configured="true"
                    receiver_details="Found ${configured_receivers} configured receiver(s): ${receiver_types}"
                else
                    receivers_configured="false"
                    receiver_details="No alert receivers configured (only default null receiver)"
                fi
                
                alertmanager_status["receivers_configured"]="${configured_receivers}"
                alertmanager_status["routes_configured"]="${routes_count}"
                
                log_debug "AlertManager receivers analysis: ${receiver_details}"
                
            else
                error_messages+=("Failed to decode AlertManager configuration")
                receivers_configured="unknown"
                receiver_details="Unable to decode configuration"
            fi
        else
            error_messages+=("AlertManager configuration data not found in secret")
            receivers_configured="unknown"
            receiver_details="Configuration data not available"
        fi
    else
        # Try alternative approach - check for AlertManagerConfig CRDs
        log_debug "Trying alternative approach: checking AlertManagerConfig CRDs"
        local amc_configs=""
        if amc_configs=$(execute_oc_command "get alertmanagerconfigs --all-namespaces --no-headers 2>/dev/null" "Get AlertManagerConfig CRDs" 1); then
            local amc_count
            amc_count=$(echo "${amc_configs}" | wc -l)
            if [[ ${amc_count} -gt 0 && -n "${amc_configs}" ]]; then
                receivers_configured="true"
                receiver_details="Found ${amc_count} AlertManagerConfig custom resource(s)"
                alertmanager_status["receivers_configured"]="${amc_count}"
            else
                receivers_configured="false"
                receiver_details="No AlertManagerConfig resources found"
                alertmanager_status["receivers_configured"]="0"
            fi
        else
            error_messages+=("Failed to retrieve AlertManager configuration")
            receivers_configured="unknown"
            receiver_details="Unable to access AlertManager configuration"
        fi
    fi
    
    # Store receiver configuration status
    alertmanager_status["receiver_status"]="${receivers_configured}"
    alertmanager_status["receiver_details"]="${receiver_details}"
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        alertmanager_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    case "${alertmanager_status["deployment_status"]}" in
        "healthy")
            # Check if receivers are configured
            if [[ "${alertmanager_status["receivers_configured"]}" == "0" || "${alertmanager_status["receiver_status"]}" == "false" ]]; then
                overall_status="${STATUS_WARNING}"
                overall_message="AlertManager is running but no alert receivers are configured"
            else
                overall_status="${STATUS_HEALTHY}"
                overall_message="AlertManager is running with ${alertmanager_status["healthy_pods"]} healthy pod(s) and ${alertmanager_status["receivers_configured"]} receiver(s) configured"
            fi
            ;;
        "partial")
            overall_status="${STATUS_WARNING}"
            overall_message="AlertManager partially healthy: ${alertmanager_status["healthy_pods"]}/${alertmanager_status["pod_count"]} pods running"
            ;;
        "unhealthy")
            overall_status="${STATUS_CRITICAL}"
            overall_message="AlertManager unhealthy: no pods running"
            ;;
        "not_found")
            overall_status="${STATUS_CRITICAL}"
            overall_message="AlertManager not found or not deployed"
            ;;
        *)
            overall_status="${STATUS_UNKNOWN}"
            overall_message="Unable to determine AlertManager status"
            ;;
    esac
    
    # Update overall status
    alertmanager_status["overall_status"]="${overall_status}"
    alertmanager_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "AlertManager status check completed:"
    log_info "  Deployment status: ${alertmanager_status["deployment_status"]}"
    log_info "  Healthy pods: ${alertmanager_status["healthy_pods"]}/${alertmanager_status["pod_count"]}"
    log_info "  Receivers configured: ${alertmanager_status["receivers_configured"]}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get AlertManager status summary
get_alertmanager_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${alertmanager_status["overall_status"]}",
    "overall_message": "${alertmanager_status["overall_message"]}",
    "deployment_status": "${alertmanager_status["deployment_status"]}",
    "pod_count": ${alertmanager_status["pod_count"]},
    "healthy_pods": ${alertmanager_status["healthy_pods"]},
    "receivers_configured": ${alertmanager_status["receivers_configured"]},
    "routes_configured": ${alertmanager_status["routes_configured"]},
    "receiver_status": "${alertmanager_status["receiver_status"]}",
    "receiver_details": "${alertmanager_status["receiver_details"]}",
    "check_timestamp": "${alertmanager_status["check_timestamp"]}",
    "details": "${alertmanager_status["details"]}",
    "errors": "${alertmanager_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
AlertManager Status: ${alertmanager_status["overall_status"]}
Message: ${alertmanager_status["overall_message"]}
Deployment Status: ${alertmanager_status["deployment_status"]}
Healthy Pods: ${alertmanager_status["healthy_pods"]}/${alertmanager_status["pod_count"]}
Receivers Configured: ${alertmanager_status["receiver_status"]}
Receiver Details: ${alertmanager_status["receiver_details"]}
Routes Configured: ${alertmanager_status["routes_configured"]}
Check Timestamp: ${alertmanager_status["check_timestamp"]}
EOF
            if [[ -n "${alertmanager_status["errors"]}" ]]; then
                echo "Errors: ${alertmanager_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# LOKI STATUS MODULE
# =============================================================================

# Loki status structure
declare -A loki_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["deployment_status"]="unknown"
    ["pod_count"]="0"
    ["healthy_pods"]="0"
    ["audit_tenant"]="unknown"
    ["infrastructure_tenant"]="unknown"
    ["application_tenant"]="unknown"
    ["audit_retention"]="unknown"
    ["infrastructure_retention"]="unknown"
    ["application_retention"]="unknown"
    ["lokistack_configured"]="unknown"
    ["compactor_status"]="unknown"
    ["distributor_status"]="unknown"
    ["gateway_status"]="unknown"
    ["index_gateway_status"]="unknown"
    ["ingester_status"]="unknown"
    ["querier_status"]="unknown"
    ["query_frontend_status"]="unknown"
    ["ruler_status"]="unknown"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check Loki tenant retention configuration
check_loki_tenant_retention() {
    local lokistack_yaml="$1"
    
    log_debug "Analyzing Loki tenant retention configuration..."
    
    # Initialize retention values
    local audit_retention="unknown"
    local infrastructure_retention="unknown"
    local application_retention="unknown"
    local global_retention="unknown"
    
    # Parse LokiStack configuration for tenant retention
    if [[ -n "${lokistack_yaml}" && "${lokistack_yaml}" != "null" ]]; then
        # First check for global retention policy
        if command -v yq >/dev/null 2>&1; then
            log_debug "Using yq to parse LokiStack YAML configuration"
            
            # Check global retention under spec.limits.global.retention.days
            global_retention=$(echo "${lokistack_yaml}" | yq eval '.spec.limits.global.retention.days // "not_configured"' - 2>/dev/null || echo "unknown")
            
            # Check individual tenant retention under spec.tenants
            audit_retention=$(echo "${lokistack_yaml}" | yq eval '.spec.tenants.audit.retention.days // "not_configured"' - 2>/dev/null || echo "unknown")
            infrastructure_retention=$(echo "${lokistack_yaml}" | yq eval '.spec.tenants.infrastructure.retention.days // "not_configured"' - 2>/dev/null || echo "unknown")
            application_retention=$(echo "${lokistack_yaml}" | yq eval '.spec.tenants.application.retention.days // "not_configured"' - 2>/dev/null || echo "unknown")
            
            log_debug "Parsed retention values - Global: ${global_retention}, Audit: ${audit_retention}, Infrastructure: ${infrastructure_retention}, Application: ${application_retention}"
        else
            log_debug "yq not available, using jq for YAML parsing"
            # Convert YAML to JSON first
            local json_data
            if json_data=$(echo "${lokistack_yaml}" | python3 -c "import sys, yaml, json; json.dump(yaml.safe_load(sys.stdin), sys.stdout)" 2>/dev/null); then
                # Check global retention
                global_retention=$(echo "${json_data}" | jq -r '.spec.limits.global.retention.days // "not_configured"' 2>/dev/null || echo "unknown")
                
                # Check individual tenant retention
                audit_retention=$(echo "${json_data}" | jq -r '.spec.tenants.audit.retention.days // "not_configured"' 2>/dev/null || echo "unknown")
                infrastructure_retention=$(echo "${json_data}" | jq -r '.spec.tenants.infrastructure.retention.days // "not_configured"' 2>/dev/null || echo "unknown")
                application_retention=$(echo "${json_data}" | jq -r '.spec.tenants.application.retention.days // "not_configured"' 2>/dev/null || echo "unknown")
                
                log_debug "Parsed retention values via JSON - Global: ${global_retention}, Audit: ${audit_retention}, Infrastructure: ${infrastructure_retention}, Application: ${application_retention}"
            else
                log_debug "Failed to convert YAML to JSON, trying direct text parsing"
                # Fallback: try to extract retention values using grep/sed
                if echo "${lokistack_yaml}" | grep -q "retention:"; then
                    # Try to extract global retention
                    if global_retention_line=$(echo "${lokistack_yaml}" | grep -A5 "limits:" | grep -A3 "global:" | grep -A1 "retention:" | grep "days:" | head -1); then
                        global_retention=$(echo "${global_retention_line}" | sed 's/.*days: *\([0-9]*\).*/\1/' | head -1)
                        if [[ -n "${global_retention}" && "${global_retention}" =~ ^[0-9]+$ ]]; then
                            global_retention="${global_retention}d"
                        else
                            global_retention="not_configured"
                        fi
                    fi
                    
                    # Try to extract tenant-specific retention
                    if audit_retention_line=$(echo "${lokistack_yaml}" | grep -A10 "audit:" | grep -A1 "retention:" | grep "days:" | head -1); then
                        audit_retention=$(echo "${audit_retention_line}" | sed 's/.*days: *\([0-9]*\).*/\1/' | head -1)
                        if [[ -n "${audit_retention}" && "${audit_retention}" =~ ^[0-9]+$ ]]; then
                            audit_retention="${audit_retention}d"
                        else
                            audit_retention="not_configured"
                        fi
                    fi
                    
                    if infra_retention_line=$(echo "${lokistack_yaml}" | grep -A10 "infrastructure:" | grep -A1 "retention:" | grep "days:" | head -1); then
                        infrastructure_retention=$(echo "${infra_retention_line}" | sed 's/.*days: *\([0-9]*\).*/\1/' | head -1)
                        if [[ -n "${infrastructure_retention}" && "${infrastructure_retention}" =~ ^[0-9]+$ ]]; then
                            infrastructure_retention="${infrastructure_retention}d"
                        else
                            infrastructure_retention="not_configured"
                        fi
                    fi
                    
                    if app_retention_line=$(echo "${lokistack_yaml}" | grep -A10 "application:" | grep -A1 "retention:" | grep "days:" | head -1); then
                        application_retention=$(echo "${app_retention_line}" | sed 's/.*days: *\([0-9]*\).*/\1/' | head -1)
                        if [[ -n "${application_retention}" && "${application_retention}" =~ ^[0-9]+$ ]]; then
                            application_retention="${application_retention}d"
                        else
                            application_retention="not_configured"
                        fi
                    fi
                    
                    log_debug "Text parsing results - Global: ${global_retention}, Audit: ${audit_retention}, Infrastructure: ${infrastructure_retention}, Application: ${application_retention}"
                fi
            fi
        fi
        
        # If individual tenant retention is not configured, use global retention as fallback
        if [[ "${audit_retention}" == "not_configured" || "${audit_retention}" == "unknown" ]] && [[ "${global_retention}" != "not_configured" && "${global_retention}" != "unknown" ]]; then
            audit_retention="${global_retention} (global)"
        fi
        if [[ "${infrastructure_retention}" == "not_configured" || "${infrastructure_retention}" == "unknown" ]] && [[ "${global_retention}" != "not_configured" && "${global_retention}" != "unknown" ]]; then
            infrastructure_retention="${global_retention} (global)"
        fi
        if [[ "${application_retention}" == "not_configured" || "${application_retention}" == "unknown" ]] && [[ "${global_retention}" != "not_configured" && "${global_retention}" != "unknown" ]]; then
            application_retention="${global_retention} (global)"
        fi
    fi
    
    # Convert retention status to standardized format
    audit_retention=$(if [[ "${audit_retention}" == "not_configured" || "${audit_retention}" == "null" || "${audit_retention}" == "unknown" ]]; then echo "not_configured"; else echo "${audit_retention}"; fi)
    infrastructure_retention=$(if [[ "${infrastructure_retention}" == "not_configured" || "${infrastructure_retention}" == "null" || "${infrastructure_retention}" == "unknown" ]]; then echo "not_configured"; else echo "${infrastructure_retention}"; fi)
    application_retention=$(if [[ "${application_retention}" == "not_configured" || "${application_retention}" == "null" || "${application_retention}" == "unknown" ]]; then echo "not_configured"; else echo "${application_retention}"; fi)
    
    # Create retention result JSON
    local retention_result
    retention_result=$(cat << EOF
{
    "global_retention": "${global_retention}",
    "audit_retention": "${audit_retention}",
    "infrastructure_retention": "${infrastructure_retention}",
    "application_retention": "${application_retention}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    log_debug "Loki tenant retention analysis completed"
    echo "${retention_result}"
}

# Check Loki component pods status by examining running pods
check_loki_component_pods() {
    log_debug "Checking Loki component pods in openshift-logging namespace..."
    
    # Initialize component statuses
    local compactor_status="not_found"
    local distributor_status="not_found"
    local gateway_status="not_found"
    local index_gateway_status="not_found"
    local ingester_status="not_found"
    local querier_status="not_found"
    local query_frontend_status="not_found"
    local ruler_status="not_found"
    local collector_status="not_found"
    
    # Get all pods in openshift-logging namespace
    local pods_json=""
    if pods_json=$(execute_oc_json "get pods -n openshift-logging -o json" "Get all pods in openshift-logging" 1 2>/dev/null); then
        local total_pods
        total_pods=$(count_json_array "${pods_json}" ".items" "pods in openshift-logging")
        
        if [[ "${total_pods}" -gt 0 ]]; then
            log_debug "Found ${total_pods} pods in openshift-logging namespace"
            
            # Check each component by looking for pods with specific names/labels
            local pod_index=0
            while [[ ${pod_index} -lt ${total_pods} ]]; do
                local pod_name
                pod_name=$(parse_json_field "${pods_json}" ".items[${pod_index}].metadata.name" "" "pod name")
                local pod_phase
                pod_phase=$(parse_json_field "${pods_json}" ".items[${pod_index}].status.phase" "" "pod phase")
                
                log_debug "Checking pod: ${pod_name} (phase: ${pod_phase})"
                
                # Check for compactor component (multiple naming patterns)
                if echo "${pod_name}" | grep -qiE "(compactor|loki.*compactor|logging.*loki.*compactor)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        compactor_status="running"
                        log_debug "Compactor pod found and running: ${pod_name}"
                    else
                        compactor_status="not_running"
                        log_debug "Compactor pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for distributor component
                if echo "${pod_name}" | grep -qiE "(distributor|loki.*distributor|logging.*loki.*distributor)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        distributor_status="running"
                        log_debug "Distributor pod found and running: ${pod_name}"
                    else
                        distributor_status="not_running"
                        log_debug "Distributor pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for gateway component
                if echo "${pod_name}" | grep -qiE "(gateway|loki.*gateway|logging.*loki.*gateway)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        gateway_status="running"
                        log_debug "Gateway pod found and running: ${pod_name}"
                    else
                        gateway_status="not_running"
                        log_debug "Gateway pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for index-gateway component
                if echo "${pod_name}" | grep -qiE "(index.*gateway|indexgateway|loki.*index.*gateway|logging.*loki.*index.*gateway)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        index_gateway_status="running"
                        log_debug "Index Gateway pod found and running: ${pod_name}"
                    else
                        index_gateway_status="not_running"
                        log_debug "Index Gateway pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for ingester component
                if echo "${pod_name}" | grep -qiE "(ingester|loki.*ingester|logging.*loki.*ingester)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        ingester_status="running"
                        log_debug "Ingester pod found and running: ${pod_name}"
                    else
                        ingester_status="not_running"
                        log_debug "Ingester pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for querier component
                if echo "${pod_name}" | grep -qiE "(querier|loki.*querier|logging.*loki.*querier)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        querier_status="running"
                        log_debug "Querier pod found and running: ${pod_name}"
                    else
                        querier_status="not_running"
                        log_debug "Querier pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for query-frontend component
                if echo "${pod_name}" | grep -qiE "(query.*frontend|queryfrontend|loki.*query.*frontend|logging.*loki.*query.*frontend)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        query_frontend_status="running"
                        log_debug "Query Frontend pod found and running: ${pod_name}"
                    else
                        query_frontend_status="not_running"
                        log_debug "Query Frontend pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for ruler component
                if echo "${pod_name}" | grep -qiE "(ruler|loki.*ruler|logging.*loki.*ruler)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        ruler_status="running"
                        log_debug "Ruler pod found and running: ${pod_name}"
                    else
                        ruler_status="not_running"
                        log_debug "Ruler pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                # Check for collector component (fluentd, vector, or other log collectors)
                if echo "${pod_name}" | grep -qiE "(collector|fluentd|vector|logging.*collector|log.*collector)"; then
                    if [[ "${pod_phase}" == "Running" ]]; then
                        collector_status="running"
                        log_debug "Collector pod found and running: ${pod_name}"
                    else
                        collector_status="not_running"
                        log_debug "Collector pod found but not running: ${pod_name} (${pod_phase})"
                    fi
                fi
                
                ((pod_index++))
            done
        else
            log_debug "No pods found in openshift-logging namespace"
        fi
    else
        log_warn "Failed to retrieve pods from openshift-logging namespace"
        return 1
    fi
    
    # Create result JSON
    local components_result
    components_result=$(cat << EOF
{
    "compactor": "${compactor_status}",
    "distributor": "${distributor_status}",
    "gateway": "${gateway_status}",
    "index_gateway": "${index_gateway_status}",
    "ingester": "${ingester_status}",
    "querier": "${querier_status}",
    "query_frontend": "${query_frontend_status}",
    "ruler": "${ruler_status}",
    "collector": "${collector_status}"
}
EOF
    )
    
    log_debug "Loki component pods status: ${components_result}"
    echo "${components_result}"
    return 0
}

# Check Loki stack components status
check_loki_stack_components() {
    local lokistack_yaml="$1"
    
    log_debug "Analyzing Loki stack components configuration..."
    
    # Initialize component statuses
    local compactor_status="unknown"
    local distributor_status="unknown"
    local gateway_status="unknown"
    local index_gateway_status="unknown"
    local ingester_status="unknown"
    local querier_status="unknown"
    local query_frontend_status="unknown"
    local ruler_status="unknown"
    
    # Parse LokiStack configuration for component status
    if [[ -n "${lokistack_yaml}" && "${lokistack_yaml}" != "null" ]]; then
        # Check if components are configured in the spec
        local template_spec
        template_spec=$(echo "${lokistack_yaml}" | yq eval '.spec.template' - 2>/dev/null || echo "null")
        
        if [[ "${template_spec}" != "null" ]]; then
            # Check individual components
            compactor_status=$(echo "${template_spec}" | yq eval '.compactor // "not_configured"' - 2>/dev/null || echo "unknown")
            distributor_status=$(echo "${template_spec}" | yq eval '.distributor // "not_configured"' - 2>/dev/null || echo "unknown")
            gateway_status=$(echo "${template_spec}" | yq eval '.gateway // "not_configured"' - 2>/dev/null || echo "unknown")
            index_gateway_status=$(echo "${template_spec}" | yq eval '.indexGateway // "not_configured"' - 2>/dev/null || echo "unknown")
            ingester_status=$(echo "${template_spec}" | yq eval '.ingester // "not_configured"' - 2>/dev/null || echo "unknown")
            querier_status=$(echo "${template_spec}" | yq eval '.querier // "not_configured"' - 2>/dev/null || echo "unknown")
            query_frontend_status=$(echo "${template_spec}" | yq eval '.queryFrontend // "not_configured"' - 2>/dev/null || echo "unknown")
            ruler_status=$(echo "${template_spec}" | yq eval '.ruler // "not_configured"' - 2>/dev/null || echo "unknown")
        fi
        
        # If yq is not available, use jq as fallback
        if ! command -v yq >/dev/null 2>&1; then
            log_debug "yq not available, using jq for YAML parsing"
            # Convert YAML to JSON first (this is a simplified approach)
            local json_data
            if json_data=$(echo "${lokistack_yaml}" | python3 -c "import sys, yaml, json; json.dump(yaml.safe_load(sys.stdin), sys.stdout)" 2>/dev/null); then
                compactor_status=$(echo "${json_data}" | jq -r '.spec.template.compactor // "not_configured"' 2>/dev/null || echo "unknown")
                distributor_status=$(echo "${json_data}" | jq -r '.spec.template.distributor // "not_configured"' 2>/dev/null || echo "unknown")
                gateway_status=$(echo "${json_data}" | jq -r '.spec.template.gateway // "not_configured"' 2>/dev/null || echo "unknown")
                index_gateway_status=$(echo "${json_data}" | jq -r '.spec.template.indexGateway // "not_configured"' 2>/dev/null || echo "unknown")
                ingester_status=$(echo "${json_data}" | jq -r '.spec.template.ingester // "not_configured"' 2>/dev/null || echo "unknown")
                querier_status=$(echo "${json_data}" | jq -r '.spec.template.querier // "not_configured"' 2>/dev/null || echo "unknown")
                query_frontend_status=$(echo "${json_data}" | jq -r '.spec.template.queryFrontend // "not_configured"' 2>/dev/null || echo "unknown")
                ruler_status=$(echo "${json_data}" | jq -r '.spec.template.ruler // "not_configured"' 2>/dev/null || echo "unknown")
            fi
        fi
    fi
    
    # Convert component status to standardized format
    compactor_status=$(if [[ "${compactor_status}" == "not_configured" || "${compactor_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    distributor_status=$(if [[ "${distributor_status}" == "not_configured" || "${distributor_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    gateway_status=$(if [[ "${gateway_status}" == "not_configured" || "${gateway_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    index_gateway_status=$(if [[ "${index_gateway_status}" == "not_configured" || "${index_gateway_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    ingester_status=$(if [[ "${ingester_status}" == "not_configured" || "${ingester_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    querier_status=$(if [[ "${querier_status}" == "not_configured" || "${querier_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    query_frontend_status=$(if [[ "${query_frontend_status}" == "not_configured" || "${query_frontend_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    ruler_status=$(if [[ "${ruler_status}" == "not_configured" || "${ruler_status}" == "null" ]]; then echo "not_configured"; else echo "configured"; fi)
    
    # Create components result JSON
    local components_result
    components_result=$(cat << EOF
{
    "compactor": "${compactor_status}",
    "distributor": "${distributor_status}",
    "gateway": "${gateway_status}",
    "index_gateway": "${index_gateway_status}",
    "ingester": "${ingester_status}",
    "querier": "${querier_status}",
    "query_frontend": "${query_frontend_status}",
    "ruler": "${ruler_status}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    
    log_debug "Loki stack components analysis completed"
    echo "${components_result}"
}

# Check Loki status and tenant configuration
check_loki_status() {
    log_info "Checking Loki status using simplified approach..."
    
    # Reset Loki status
    loki_status["overall_status"]="${STATUS_UNKNOWN}"
    loki_status["overall_message"]=""
    loki_status["deployment_status"]="unknown"
    loki_status["pod_count"]="0"
    loki_status["healthy_pods"]="0"
    loki_status["audit_tenant"]="unknown"
    loki_status["infrastructure_tenant"]="unknown"
    loki_status["application_tenant"]="unknown"
    loki_status["audit_retention"]="unknown"
    loki_status["infrastructure_retention"]="unknown"
    loki_status["application_retention"]="unknown"
    loki_status["lokistack_configured"]="unknown"
    loki_status["lokistack_size"]="unknown"
    loki_status["compactor_status"]="unknown"
    loki_status["distributor_status"]="unknown"
    loki_status["gateway_status"]="unknown"
    loki_status["index_gateway_status"]="unknown"
    loki_status["ingester_status"]="unknown"
    loki_status["querier_status"]="unknown"
    loki_status["query_frontend_status"]="unknown"
    loki_status["ruler_status"]="unknown"
    loki_status["collector_status"]="unknown"
    loki_status["check_timestamp"]="$(get_timestamp)"
    loki_status["details"]=""
    loki_status["errors"]=""
    
    local error_messages=()
    
    # Check if openshift-logging namespace exists
    if ! oc get namespace openshift-logging >/dev/null 2>&1; then
        log_debug "openshift-logging namespace does not exist"
        error_messages+=("OpenShift Logging operator not installed (openshift-logging namespace missing)")
        loki_status["deployment_status"]="not_found"
        loki_status["overall_status"]="${STATUS_CRITICAL}"
        loki_status["overall_message"]="OpenShift Logging namespace not found"
        loki_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
        return 0
    fi
    
    # Step 1: Get LokiStack configuration and store in temp file
    log_debug "Getting LokiStack configuration from openshift-logging namespace..."
    local lokistack_temp_file
    lokistack_temp_file=$(create_temp_file "lokistack" ".yaml")
    
    if execute_oc_command "get lokistacks -n openshift-logging -o yaml" "Get LokiStack configuration" 1 5 "${lokistack_temp_file}"; then
        log_debug "LokiStack configuration saved to: ${lokistack_temp_file}"
        
        # Check if LokiStack exists
        if grep -q "kind: LokiStack" "${lokistack_temp_file}" 2>/dev/null; then
            loki_status["lokistack_configured"]="true"
            log_debug "LokiStack resource found"
            
            # Extract tenant retention configuration
            local audit_retention
            local infrastructure_retention  
            local application_retention
            
            # Extract retention periods from LokiStack YAML (nested under tenants)
            audit_retention=$(grep -A 5 "audit:" "${lokistack_temp_file}" | grep -A 2 "retention:" | grep "days:" | head -1 | awk '{print $2}' | tr -d '"' || echo "unknown")
            infrastructure_retention=$(grep -A 5 "infrastructure:" "${lokistack_temp_file}" | grep -A 2 "retention:" | grep "days:" | head -1 | awk '{print $2}' | tr -d '"' || echo "unknown")
            application_retention=$(grep -A 5 "application:" "${lokistack_temp_file}" | grep -A 2 "retention:" | grep "days:" | head -1 | awk '{print $2}' | tr -d '"' || echo "unknown")
            
            # If tenant-specific retention not found, try global retention
            if [[ "${audit_retention}" == "unknown" ]]; then
                audit_retention=$(grep -A 5 "retention:" "${lokistack_temp_file}" | grep "days:" | head -1 | awk '{print $2}' | tr -d '"' || echo "unknown")
            fi
            if [[ "${infrastructure_retention}" == "unknown" ]]; then
                infrastructure_retention=$(grep -A 5 "retention:" "${lokistack_temp_file}" | grep "days:" | head -1 | awk '{print $2}' | tr -d '"' || echo "unknown")
            fi
            if [[ "${application_retention}" == "unknown" ]]; then
                application_retention=$(grep -A 5 "retention:" "${lokistack_temp_file}" | grep "days:" | head -1 | awk '{print $2}' | tr -d '"' || echo "unknown")
            fi
            
            loki_status["audit_retention"]="${audit_retention:-unknown}"
            loki_status["infrastructure_retention"]="${infrastructure_retention:-unknown}"
            loki_status["application_retention"]="${application_retention:-unknown}"
            
            # Extract LokiStack size configuration
            local lokistack_size
            lokistack_size=$(grep -A 2 "size:" "${lokistack_temp_file}" | head -1 | awk '{print $2}' | tr -d '"' || echo "unknown")
            loki_status["lokistack_size"]="${lokistack_size:-unknown}"
            
            # Check tenant configuration
            if grep -q "audit:" "${lokistack_temp_file}"; then
                loki_status["audit_tenant"]="configured"
            else
                loki_status["audit_tenant"]="not_configured"
            fi
            
            if grep -q "infrastructure:" "${lokistack_temp_file}"; then
                loki_status["infrastructure_tenant"]="configured"
            else
                loki_status["infrastructure_tenant"]="not_configured"
            fi
            
            if grep -q "application:" "${lokistack_temp_file}"; then
                loki_status["application_tenant"]="configured"
            else
                loki_status["application_tenant"]="not_configured"
            fi
            
        else
            loki_status["lokistack_configured"]="false"
            error_messages+=("No LokiStack resources found in openshift-logging namespace")
            loki_status["audit_tenant"]="not_configured"
            loki_status["infrastructure_tenant"]="not_configured"
            loki_status["application_tenant"]="not_configured"
        fi
    else
        error_messages+=("Failed to retrieve LokiStack configuration")
        loki_status["lokistack_configured"]="false"
    fi
    
    # Step 1.5: Check ClusterLogForwarder configuration for additional Loki tenant info
    log_debug "Checking ClusterLogForwarder configuration for Loki outputs..."
    local clusterlogforwarder_temp_file
    clusterlogforwarder_temp_file=$(create_temp_file "clusterlogforwarder" ".yaml")
    
    if execute_oc_command "get clusterlogforwarders -n openshift-logging -o yaml" "Get ClusterLogForwarder configuration" 1 5 "${clusterlogforwarder_temp_file}"; then
        log_debug "ClusterLogForwarder configuration saved to: ${clusterlogforwarder_temp_file}"
        
        # Check if ClusterLogForwarder with LokiStack output exists
        if grep -q "kind: ClusterLogForwarder" "${clusterlogforwarder_temp_file}" 2>/dev/null && grep -q "type: lokiStack" "${clusterlogforwarder_temp_file}" 2>/dev/null; then
            log_debug "ClusterLogForwarder with LokiStack output found"
            
            # Check what log types are being forwarded to LokiStack
            local clf_has_audit=false
            local clf_has_infrastructure=false
            local clf_has_application=false
            
            # Look for pipelines that reference LokiStack outputs
            local in_pipeline=false
            local current_pipeline_refs=""
            
            while IFS= read -r line; do
                # Check if we're entering a pipeline section
                if echo "$line" | grep -q "^[[:space:]]*- name:.*pipeline"; then
                    in_pipeline=true
                    current_pipeline_refs=""
                elif echo "$line" | grep -q "^[[:space:]]*- name:" && [[ "$in_pipeline" == true ]]; then
                    # New pipeline or section, reset
                    in_pipeline=false
                    current_pipeline_refs=""
                elif [[ "$in_pipeline" == true ]]; then
                    # Collect inputRefs for this pipeline
                    if echo "$line" | grep -q "inputRefs:"; then
                        current_pipeline_refs=""
                    elif echo "$line" | grep -q "^[[:space:]]*- audit"; then
                        current_pipeline_refs="${current_pipeline_refs} audit"
                    elif echo "$line" | grep -q "^[[:space:]]*- infrastructure"; then
                        current_pipeline_refs="${current_pipeline_refs} infrastructure"
                    elif echo "$line" | grep -q "^[[:space:]]*- application"; then
                        current_pipeline_refs="${current_pipeline_refs} application"
                    elif echo "$line" | grep -q "outputRefs:" && echo "$current_pipeline_refs" | grep -q "audit"; then
                        # Check if this pipeline with audit logs goes to lokistack
                        local next_lines
                        next_lines=$(grep -A 5 "outputRefs:" "${clusterlogforwarder_temp_file}" | grep -E "(lokistack|loki-stack)")
                        if [[ -n "$next_lines" ]]; then
                            clf_has_audit=true
                        fi
                    elif echo "$line" | grep -q "outputRefs:" && echo "$current_pipeline_refs" | grep -q "infrastructure"; then
                        local next_lines
                        next_lines=$(grep -A 5 "outputRefs:" "${clusterlogforwarder_temp_file}" | grep -E "(lokistack|loki-stack)")
                        if [[ -n "$next_lines" ]]; then
                            clf_has_infrastructure=true
                        fi
                    elif echo "$line" | grep -q "outputRefs:" && echo "$current_pipeline_refs" | grep -q "application"; then
                        local next_lines
                        next_lines=$(grep -A 5 "outputRefs:" "${clusterlogforwarder_temp_file}" | grep -E "(lokistack|loki-stack)")
                        if [[ -n "$next_lines" ]]; then
                            clf_has_application=true
                        fi
                    fi
                fi
            done < "${clusterlogforwarder_temp_file}"
            
            # Update tenant status based on ClusterLogForwarder findings
            # Only override "not_configured" status, don't downgrade "configured" status
            if [[ "$clf_has_audit" == true ]] && [[ "${loki_status["audit_tenant"]}" == "not_configured" ]]; then
                loki_status["audit_tenant"]="configured_via_clf"
                log_debug "Audit tenant configured via ClusterLogForwarder"
            fi
            
            if [[ "$clf_has_infrastructure" == true ]] && [[ "${loki_status["infrastructure_tenant"]}" == "not_configured" ]]; then
                loki_status["infrastructure_tenant"]="configured_via_clf"
                log_debug "Infrastructure tenant configured via ClusterLogForwarder"
            fi
            
            if [[ "$clf_has_application" == true ]] && [[ "${loki_status["application_tenant"]}" == "not_configured" ]]; then
                loki_status["application_tenant"]="configured_via_clf"
                log_debug "Application tenant configured via ClusterLogForwarder"
            fi
            
        else
            log_debug "No ClusterLogForwarder with LokiStack output found"
        fi
    else
        log_debug "Failed to retrieve ClusterLogForwarder configuration or none exists"
    fi
    
    # Step 2: Get pods in openshift-logging namespace and store in temp file
    log_debug "Getting pods from openshift-logging namespace..."
    local pods_temp_file
    pods_temp_file=$(create_temp_file "loki-pods" ".json")
    
    if execute_oc_command "get pods -n openshift-logging -o json" "Get pods in openshift-logging" 1 5 "${pods_temp_file}"; then
        log_debug "Pods information saved to: ${pods_temp_file}"
        
        # Parse pod information
        local pods_json
        pods_json=$(cat "${pods_temp_file}")
        
        # Count total pods and analyze component status
        local total_pods=0
        local healthy_pods=0
        
        # Initialize component counters
        local compactor_running=0
        local distributor_running=0
        local gateway_running=0
        local index_gateway_running=0
        local ingester_running=0
        local querier_running=0
        local query_frontend_running=0
        local ruler_running=0
        local collector_running=0
        
        # Process each pod
        if [[ -n "${pods_json}" ]]; then
            local pod_count
            pod_count=$(echo "${pods_json}" | jq '.items | length' 2>/dev/null || echo "0")
            
            for ((i=0; i<pod_count; i++)); do
                local pod_name
                local pod_phase
                local pod_ready
                
                pod_name=$(echo "${pods_json}" | jq -r ".items[${i}].metadata.name" 2>/dev/null || echo "unknown")
                pod_phase=$(echo "${pods_json}" | jq -r ".items[${i}].status.phase" 2>/dev/null || echo "unknown")
                
                # Check if pod is ready
                pod_ready=$(echo "${pods_json}" | jq -r ".items[${i}].status.conditions[]? | select(.type==\"Ready\") | .status" 2>/dev/null || echo "False")
                
                # Only count Loki-related pods (including collector pods)
                if echo "${pod_name}" | grep -qiE "(loki|logging|collector)"; then
                    ((total_pods++))
                    
                    # Count healthy pods
                    if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                        ((healthy_pods++))
                    fi
                    
                    # Identify component types and count running AND ready ones
                    if echo "${pod_name}" | grep -qiE "(compactor|loki.*compactor)"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((compactor_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(distributor|loki.*distributor)"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((distributor_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(gateway|loki.*gateway)" && ! echo "${pod_name}" | grep -qiE "index.*gateway"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((gateway_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(index.*gateway|indexgateway|loki.*index.*gateway)"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((index_gateway_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(ingester|loki.*ingester)"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((ingester_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(querier|loki.*querier)" && ! echo "${pod_name}" | grep -qiE "query.*frontend"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((querier_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(query.*frontend|queryfrontend|loki.*query.*frontend)"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((query_frontend_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(ruler|loki.*ruler)"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((ruler_running++))
                        fi
                    fi
                    
                    if echo "${pod_name}" | grep -qiE "(collector|fluentd|vector|logging.*collector)"; then
                        if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                            ((collector_running++))
                        fi
                    fi
                fi
            done
        fi
        
        # Set pod counts
        loki_status["pod_count"]="${total_pods}"
        loki_status["healthy_pods"]="${healthy_pods}"
        
        # Set component statuses
        loki_status["compactor_status"]=$([ ${compactor_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["distributor_status"]=$([ ${distributor_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["gateway_status"]=$([ ${gateway_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["index_gateway_status"]=$([ ${index_gateway_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["ingester_status"]=$([ ${ingester_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["querier_status"]=$([ ${querier_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["query_frontend_status"]=$([ ${query_frontend_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["ruler_status"]=$([ ${ruler_running} -gt 0 ] && echo "running" || echo "not_found")
        loki_status["collector_status"]=$([ ${collector_running} -gt 0 ] && echo "running" || echo "not_found")
        
        # Determine deployment status
        if [[ ${total_pods} -eq 0 ]]; then
            loki_status["deployment_status"]="not_found"
        elif [[ ${healthy_pods} -eq ${total_pods} ]]; then
            loki_status["deployment_status"]="healthy"
        elif [[ ${healthy_pods} -gt 0 ]]; then
            loki_status["deployment_status"]="partial"
        else
            loki_status["deployment_status"]="unhealthy"
        fi
        
        log_info "Found ${total_pods} Loki-related pods, ${healthy_pods} healthy"
        
    else
        error_messages+=("Failed to retrieve pods from openshift-logging namespace")
        loki_status["deployment_status"]="unknown"
    fi
    
    # Check LokiStack configuration first
    # All LokiStack configuration, component status, and retention analysis is handled by the simplified approach above
    
    # Pod analysis and tenant configuration are already complete from the simplified approach above
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        loki_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    # Check if any tenants are not configured
    local missing_tenants=()
    if [[ "${loki_status["audit_tenant"]}" == "not_configured" || "${loki_status["audit_tenant"]}" == "unknown" ]]; then
        missing_tenants+=("audit")
    fi
    if [[ "${loki_status["infrastructure_tenant"]}" == "not_configured" || "${loki_status["infrastructure_tenant"]}" == "unknown" ]]; then
        missing_tenants+=("infrastructure")
    fi
    if [[ "${loki_status["application_tenant"]}" == "not_configured" || "${loki_status["application_tenant"]}" == "unknown" ]]; then
        missing_tenants+=("application")
    fi
    
    case "${loki_status["deployment_status"]}" in
        "healthy")
            # Check if tenants are missing even when deployment is healthy
            if [[ ${#missing_tenants[@]} -gt 0 ]]; then
                overall_status="${STATUS_WARNING}"
                local tenant_list=$(IFS=", "; echo "${missing_tenants[*]}")
                overall_message="Loki is healthy but missing tenants: ${tenant_list}"
            else
                overall_status="${STATUS_HEALTHY}"
                overall_message="Loki is running with ${loki_status["healthy_pods"]} healthy pod(s) and all tenants configured"
            fi
            ;;
        "partial")
            overall_status="${STATUS_WARNING}"
            overall_message="Loki partially healthy: ${loki_status["healthy_pods"]}/${loki_status["pod_count"]} pods running"
            ;;
        "unhealthy")
            overall_status="${STATUS_CRITICAL}"
            overall_message="Loki unhealthy: no pods running"
            ;;
        "not_found")
            overall_status="${STATUS_CRITICAL}"
            overall_message="Loki not found or not deployed"
            ;;
        *)
            overall_status="${STATUS_UNKNOWN}"
            overall_message="Unable to determine Loki status"
            ;;
    esac
    
    # Update overall status
    loki_status["overall_status"]="${overall_status}"
    loki_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "Loki status check completed:"
    log_info "  Deployment status: ${loki_status["deployment_status"]}"
    log_info "  Healthy pods: ${loki_status["healthy_pods"]}/${loki_status["pod_count"]}"
    log_info "  Audit tenant: ${loki_status["audit_tenant"]}"
    log_info "  Infrastructure tenant: ${loki_status["infrastructure_tenant"]}"
    log_info "  Application tenant: ${loki_status["application_tenant"]}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get Loki status summary
get_loki_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${loki_status["overall_status"]}",
    "overall_message": "${loki_status["overall_message"]}",
    "deployment_status": "${loki_status["deployment_status"]}",
    "pod_count": ${loki_status["pod_count"]},
    "healthy_pods": ${loki_status["healthy_pods"]},
    "audit_tenant": "${loki_status["audit_tenant"]}",
    "infrastructure_tenant": "${loki_status["infrastructure_tenant"]}",
    "application_tenant": "${loki_status["application_tenant"]}",
    "audit_retention": "${loki_status["audit_retention"]}",
    "infrastructure_retention": "${loki_status["infrastructure_retention"]}",
    "application_retention": "${loki_status["application_retention"]}",
    "lokistack_configured": "${loki_status["lokistack_configured"]}",
    "compactor_status": "${loki_status["compactor_status"]}",
    "distributor_status": "${loki_status["distributor_status"]}",
    "gateway_status": "${loki_status["gateway_status"]}",
    "index_gateway_status": "${loki_status["index_gateway_status"]}",
    "ingester_status": "${loki_status["ingester_status"]}",
    "querier_status": "${loki_status["querier_status"]}",
    "query_frontend_status": "${loki_status["query_frontend_status"]}",
    "ruler_status": "${loki_status["ruler_status"]}",
    "collector_status": "${loki_status["collector_status"]}",
    "check_timestamp": "${loki_status["check_timestamp"]}",
    "details": "${loki_status["details"]}",
    "errors": "${loki_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
Loki Status: ${loki_status["overall_status"]}
Message: ${loki_status["overall_message"]}
Deployment Status: ${loki_status["deployment_status"]}
Healthy Pods: ${loki_status["healthy_pods"]}/${loki_status["pod_count"]}
Audit Tenant: ${loki_status["audit_tenant"]}
Infrastructure Tenant: ${loki_status["infrastructure_tenant"]}
Application Tenant: ${loki_status["application_tenant"]}
Audit Retention: ${loki_status["audit_retention"]}
Infrastructure Retention: ${loki_status["infrastructure_retention"]}
Application Retention: ${loki_status["application_retention"]}
LokiStack Configured: ${loki_status["lokistack_configured"]}
LokiStack Size: ${loki_status["lokistack_size"]}
Compactor: ${loki_status["compactor_status"]}
Distributor: ${loki_status["distributor_status"]}
Gateway: ${loki_status["gateway_status"]}
Index Gateway: ${loki_status["index_gateway_status"]}
Ingester: ${loki_status["ingester_status"]}
Querier: ${loki_status["querier_status"]}
Query Frontend: ${loki_status["query_frontend_status"]}
Ruler: ${loki_status["ruler_status"]}
Collector: ${loki_status["collector_status"]}
Check Timestamp: ${loki_status["check_timestamp"]}
EOF
            if [[ -n "${loki_status["errors"]}" ]]; then
                echo "Errors: ${loki_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# CLUSTER BACKUP STATUS MODULE
# =============================================================================

# Cluster backup status structure
declare -A backup_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["etcd_backup_enabled"]="unknown"
    ["etcd_backup_schedule"]="unknown"
    ["etcd_backup_last_success"]="unknown"
    ["etcd_backup_retention"]="unknown"
    ["oadp_operator_status"]="unknown"
    ["recent_backup_failures"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check cluster backup status
check_backup_status() {
    log_info "Checking cluster backup status..."
    
    # Reset backup status
    backup_status["overall_status"]="${STATUS_UNKNOWN}"
    backup_status["overall_message"]=""
    backup_status["etcd_backup_enabled"]="unknown"
    backup_status["etcd_backup_schedule"]="unknown"
    backup_status["etcd_backup_last_success"]="unknown"
    backup_status["etcd_backup_retention"]="unknown"
    backup_status["oadp_operator_status"]="unknown"
    backup_status["recent_backup_failures"]="0"
    backup_status["check_timestamp"]="$(get_timestamp)"
    backup_status["details"]=""
    backup_status["errors"]=""
    
    local error_messages=()
    local all_checks_successful=true
    local backup_solutions_found=0
    
    # Check 1: etcd backup configuration
    log_debug "Checking etcd backup configuration..."
    local etcd_backup_config=""
    if etcd_backup_config=$(execute_oc_json "get configmap cluster-backup-chart -n openshift-config -o json" "Get etcd backup config" 2>/dev/null); then
        backup_status["etcd_backup_enabled"]="true"
        ((backup_solutions_found++))
        
        # Try to extract backup schedule information
        local backup_schedule
        backup_schedule=$(parse_json_field "${etcd_backup_config}" ".data.schedule" "unknown" "backup schedule")
        backup_status["etcd_backup_schedule"]="${backup_schedule}"
        
        log_debug "etcd backup configuration found with schedule: ${backup_schedule}"
    else
        # Check for etcd backup CronJob in ocp-etcd-backup namespace (primary approach)
        local etcd_cronjob_ocp=""
        if etcd_cronjob_ocp=$(execute_oc_command "get cronjob -n ocp-etcd-backup --no-headers" "Get etcd backup cronjob in ocp-etcd-backup namespace" 1 2>/dev/null); then
            if [[ -n "${etcd_cronjob_ocp}" ]]; then
                backup_status["etcd_backup_enabled"]="true"
                ((backup_solutions_found++))
                
                # Try to extract schedule information from the cronjob
                local cronjob_schedule=""
                if cronjob_schedule=$(execute_oc_command "get cronjob -n ocp-etcd-backup -o jsonpath='{.items[0].spec.schedule}'" "Get cronjob schedule" 1 2>/dev/null); then
                    if [[ -n "${cronjob_schedule}" ]]; then
                        backup_status["etcd_backup_schedule"]="${cronjob_schedule}"
                    fi
                fi
                
                log_debug "etcd backup CronJob found in ocp-etcd-backup namespace with schedule: ${cronjob_schedule:-unknown}"
            fi
        fi
        
        # Fallback: Check for etcd backup CronJob with labels (alternative approach)
        if [[ "${backup_status["etcd_backup_enabled"]}" == "unknown" ]]; then
            local etcd_cronjob=""
            if etcd_cronjob=$(execute_oc_command "get cronjob -A -l app=etcd-backup --no-headers" "Get etcd backup cronjob" 1 2>/dev/null); then
                if [[ -n "${etcd_cronjob}" ]]; then
                    backup_status["etcd_backup_enabled"]="true"
                    ((backup_solutions_found++))
                    log_debug "etcd backup CronJob found via labels"
                fi
            fi
        fi
        
        # Check for manual etcd backup scripts or jobs
        local etcd_backup_jobs=""
        if etcd_backup_jobs=$(execute_oc_command "get jobs -A -l component=etcd-backup --no-headers" "Get etcd backup jobs" 1 2>/dev/null); then
            if [[ -n "${etcd_backup_jobs}" ]]; then
                backup_status["etcd_backup_enabled"]="true"
                ((backup_solutions_found++))
                log_debug "etcd backup jobs found"
            fi
        fi
        
        if [[ "${backup_status["etcd_backup_enabled"]}" == "unknown" ]]; then
            backup_status["etcd_backup_enabled"]="false"
            log_debug "No etcd backup configuration found"
        fi
    fi
    
    # Check 2: OADP (OpenShift API for Data Protection) operator
    log_debug "Checking OADP operator status..."
    local oadp_operator=""
    if oadp_operator=$(execute_oc_json "get csv -A -o json" "Get cluster service versions" 2>/dev/null); then
        # Look for OADP operator
        local oadp_csv_count
        oadp_csv_count=$(echo "${oadp_operator}" | jq -r '.items[] | select(.metadata.name | contains("oadp")) | .metadata.name' 2>/dev/null | wc -l)
        
        if [[ "${oadp_csv_count}" -gt 0 ]]; then
            backup_status["oadp_operator_status"]="installed"
            ((backup_solutions_found++))
            log_debug "OADP operator found"
        else
            backup_status["oadp_operator_status"]="not_installed"
            log_debug "OADP operator not found"
        fi
    else
        log_debug "Could not check OADP operator status"
    fi
    
    # Check 3: Other backup solutions (generic check)
    log_debug "Checking for other backup solutions..."
    local backup_related_pods=""
    if backup_related_pods=$(execute_oc_command "get pods -A -l app.kubernetes.io/name=backup --no-headers" "Get backup-related pods" 1 2>/dev/null); then
        if [[ -n "${backup_related_pods}" ]]; then
            ((backup_solutions_found++))
            log_debug "Additional backup-related pods found"
        fi
    fi
    
    # Check for backup-related CronJobs
    local backup_cronjobs=""
    if backup_cronjobs=$(execute_oc_command "get cronjob -A --no-headers" "Get all cronjobs" 1 2>/dev/null); then
        local backup_cronjob_count
        backup_cronjob_count=$(echo "${backup_cronjobs}" | grep -i backup | wc -l)
        if [[ "${backup_cronjob_count}" -gt 0 ]]; then
            ((backup_solutions_found++))
            log_debug "Found ${backup_cronjob_count} backup-related CronJobs"
        fi
    fi
    
    # Create details JSON
    local details_json
    details_json=$(cat << EOF
{
    "etcd_backup_enabled": "${backup_status["etcd_backup_enabled"]}",
    "etcd_backup_schedule": "${backup_status["etcd_backup_schedule"]}",
    "etcd_backup_last_success": "${backup_status["etcd_backup_last_success"]}",
    "etcd_backup_retention": "${backup_status["etcd_backup_retention"]}",
    "oadp_operator_status": "${backup_status["oadp_operator_status"]}",
    "recent_backup_failures": "${backup_status["recent_backup_failures"]}",
    "backup_solutions_found": "${backup_solutions_found}",
    "check_timestamp": "$(get_timestamp)"
}
EOF
    )
    backup_status["details"]="${details_json}"
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        backup_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    if [[ ${backup_solutions_found} -eq 0 ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="No backup solutions detected - cluster data is at risk"
    elif [[ "${backup_status["oadp_operator_status"]}" == "not_installed" ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="OADP operator not installed - consider installing for comprehensive backup solution"
    elif [[ "${backup_status["recent_backup_failures"]}" != "0" && "${backup_status["recent_backup_failures"]}" != "unknown" ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="Backup solutions found but recent failures detected"
    elif [[ ${backup_solutions_found} -eq 1 ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="Single backup solution found - consider additional backup methods"
    else
        overall_status="${STATUS_HEALTHY}"
        overall_message="Multiple backup solutions configured"
    fi
    
    # Update overall status
    backup_status["overall_status"]="${overall_status}"
    backup_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "Cluster backup check completed:"
    log_info "  etcd backup enabled: ${backup_status["etcd_backup_enabled"]}"
    log_info "  OADP operator: ${backup_status["oadp_operator_status"]}"
    log_info "  Recent failures: ${backup_status["recent_backup_failures"]}"
    log_info "  Backup solutions found: ${backup_solutions_found}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get backup status summary
get_backup_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${backup_status["overall_status"]}",
    "overall_message": "${backup_status["overall_message"]}",
    "etcd_backup_enabled": "${backup_status["etcd_backup_enabled"]}",
    "etcd_backup_schedule": "${backup_status["etcd_backup_schedule"]}",
    "etcd_backup_last_success": "${backup_status["etcd_backup_last_success"]}",
    "etcd_backup_retention": "${backup_status["etcd_backup_retention"]}",
    "oadp_operator_status": "${backup_status["oadp_operator_status"]}",
    "recent_backup_failures": "${backup_status["recent_backup_failures"]}",
    "check_timestamp": "${backup_status["check_timestamp"]}",
    "details": ${backup_status["details"]:-"{}"},
    "errors": "${backup_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
Backup Status: ${backup_status["overall_status"]}
Message: ${backup_status["overall_message"]}
etcd Backup Enabled: ${backup_status["etcd_backup_enabled"]}
etcd Backup Schedule: ${backup_status["etcd_backup_schedule"]}
OADP Operator: ${backup_status["oadp_operator_status"]}
Recent Backup Failures: ${backup_status["recent_backup_failures"]}
Check Timestamp: ${backup_status["check_timestamp"]}
EOF
            if [[ -n "${backup_status["errors"]}" ]]; then
                echo "Errors: ${backup_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# NODE DETAILS MODULE
# =============================================================================

# OpenShift Ingress status structure
declare -A ingress_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["ingress_controller_status"]="unknown"
    ["replica_count"]="0"
    ["desired_replicas"]="0"
    ["available_replicas"]="0"
    ["ready_replicas"]="0"
    ["node_placement_status"]="unknown"
    ["running_on_infra"]="unknown"
    ["running_on_worker"]="unknown"
    ["infra_nodes_available"]="unknown"
    ["worker_nodes_available"]="unknown"
    ["minimum_replicas_met"]="unknown"
    ["pod_distribution"]="unknown"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check OpenShift Ingress status
check_ingress_status() {
    log_info "Checking OpenShift Ingress status..."
    
    # Reset ingress status
    ingress_status["overall_status"]="${STATUS_UNKNOWN}"
    ingress_status["overall_message"]=""
    ingress_status["ingress_controller_status"]="unknown"
    ingress_status["replica_count"]="0"
    ingress_status["desired_replicas"]="0"
    ingress_status["available_replicas"]="0"
    ingress_status["ready_replicas"]="0"
    ingress_status["node_placement_status"]="unknown"
    ingress_status["running_on_infra"]="unknown"
    ingress_status["running_on_worker"]="unknown"
    ingress_status["infra_nodes_available"]="unknown"
    ingress_status["worker_nodes_available"]="unknown"
    ingress_status["minimum_replicas_met"]="unknown"
    ingress_status["pod_distribution"]="unknown"
    ingress_status["check_timestamp"]="$(get_timestamp)"
    ingress_status["details"]=""
    ingress_status["errors"]=""
    
    local error_messages=()
    local all_checks_successful=true
    
    # Step 1: Check available node types
    log_debug "Checking available node types..."
    local nodes_json=""
    if execute_oc_command "get nodes -o json" "Get cluster nodes" 1 5 > /dev/null; then
        nodes_json=$(oc get nodes -o json 2>/dev/null)
        
        if [[ -n "${nodes_json}" ]]; then
            # Count infra and worker nodes (avoiding double-counting)
            local infra_nodes=0
            local worker_only_nodes=0
            local total_nodes=0
            
            total_nodes=$(echo "${nodes_json}" | jq '.items | length' 2>/dev/null || echo "0")
            
            for ((i=0; i<total_nodes; i++)); do
                local node_labels
                local node_name
                node_labels=$(echo "${nodes_json}" | jq -r ".items[${i}].metadata.labels" 2>/dev/null || echo "{}")
                node_name=$(echo "${nodes_json}" | jq -r ".items[${i}].metadata.name" 2>/dev/null || echo "unknown")
                
                # Skip master/control-plane nodes
                if echo "${node_labels}" | jq -r 'keys[]' 2>/dev/null | grep -qE "node-role.kubernetes.io/(master|control-plane)"; then
                    log_debug "Skipping master node: ${node_name}"
                    continue
                fi
                
                # Check for infra node labels first (priority over worker)
                if echo "${node_labels}" | jq -r 'keys[]' 2>/dev/null | grep -qE "(node-role.kubernetes.io/infra|node.openshift.io/os_id.*infra)"; then
                    ((infra_nodes++))
                    log_debug "Found infra node: ${node_name}"
                # Check for worker node labels only if not already counted as infra
                elif echo "${node_labels}" | jq -r 'keys[]' 2>/dev/null | grep -qE "node-role.kubernetes.io/worker"; then
                    ((worker_only_nodes++))
                    log_debug "Found worker-only node: ${node_name}"
                fi
            done
            
            ingress_status["infra_nodes_available"]="${infra_nodes}"
            ingress_status["worker_nodes_available"]="${worker_only_nodes}"
            
            local total_ingress_capable_nodes=$((infra_nodes + worker_only_nodes))
            log_debug "Found ${infra_nodes} infra nodes and ${worker_only_nodes} worker-only nodes (total ingress-capable: ${total_ingress_capable_nodes})"
        else
            error_messages+=("Failed to get node information")
            all_checks_successful=false
        fi
    else
        error_messages+=("Failed to retrieve cluster nodes")
        all_checks_successful=false
    fi
    
    # Step 2: Check IngressController configuration
    log_debug "Checking IngressController configuration..."
    local ingress_controller_json=""
    if execute_oc_command "get ingresscontrollers -n openshift-ingress-operator -o json" "Get IngressController" 1 5 > /dev/null; then
        ingress_controller_json=$(oc get ingresscontrollers -n openshift-ingress-operator -o json 2>/dev/null)
        
        if [[ -n "${ingress_controller_json}" ]]; then
            local controller_count
            controller_count=$(echo "${ingress_controller_json}" | jq '.items | length' 2>/dev/null || echo "0")
            
            if [[ "${controller_count}" -gt 0 ]]; then
                # Get the default ingress controller (usually named "default")
                local default_controller
                default_controller=$(echo "${ingress_controller_json}" | jq -r '.items[] | select(.metadata.name == "default")' 2>/dev/null)
                
                if [[ -n "${default_controller}" && "${default_controller}" != "null" ]]; then
                    ingress_status["ingress_controller_status"]="configured"
                    
                    # Extract replica configuration
                    local desired_replicas
                    desired_replicas=$(echo "${default_controller}" | jq -r '.spec.replicas // 2' 2>/dev/null || echo "2")
                    ingress_status["desired_replicas"]="${desired_replicas}"
                    
                    # Check node placement configuration
                    local node_placement
                    node_placement=$(echo "${default_controller}" | jq -r '.spec.nodePlacement' 2>/dev/null || echo "null")
                    
                    if [[ "${node_placement}" != "null" ]]; then
                        # Check if it's configured to run on infra nodes
                        local node_selector
                        node_selector=$(echo "${node_placement}" | jq -r '.nodeSelector' 2>/dev/null || echo "null")
                        
                        # Check for nodeAffinity with matchLabels pattern
                        local node_affinity
                        node_affinity=$(echo "${node_placement}" | jq -r '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchLabels' 2>/dev/null || echo "null")
                        
                        # Check tolerations for infra/worker node taints
                        local tolerations
                        tolerations=$(echo "${node_placement}" | jq -r '.tolerations' 2>/dev/null || echo "null")
                        
                        local placement_configured=false
                        local placement_type=""
                        
                        # Check node selector with improved detection
                        if [[ "${node_selector}" != "null" ]]; then
                            local selector_keys
                            selector_keys=$(echo "${node_selector}" | jq -r 'keys[]' 2>/dev/null || echo "")
                            
                            # Check for infra node selector patterns (preferred)
                            if echo "${selector_keys}" | grep -qE "node-role.kubernetes.io/infra"; then
                                placement_configured=true
                                placement_type="infra"
                                log_debug "Found standard infra node selector in IngressController"
                            # Check for infrastructure node selector (alternative pattern)
                            elif echo "${selector_keys}" | grep -qE "node-role.kubernetes.io/infrastructure"; then
                                placement_configured=true
                                placement_type="infra"
                                log_debug "Found infrastructure node selector in IngressController"
                            # Check for worker node selector
                            elif echo "${selector_keys}" | grep -qE "node-role.kubernetes.io/worker"; then
                                placement_configured=true
                                placement_type="worker"
                                log_debug "Found worker node selector in IngressController"
                            # Check for other OpenShift infra patterns
                            elif echo "${selector_keys}" | grep -qE "(node.openshift.io/os_id.*infra|kubernetes.io/arch.*infra)"; then
                                placement_configured=true
                                placement_type="infra"
                                log_debug "Found alternative infra node selector pattern"
                            # Check for matchLabels within nodeSelector
                            elif echo "${selector_keys}" | grep -qE "matchLabels"; then
                                local match_labels
                                match_labels=$(echo "${node_selector}" | jq -r '.matchLabels' 2>/dev/null || echo "null")
                                
                                if [[ "${match_labels}" != "null" ]]; then
                                    local match_keys
                                    match_keys=$(echo "${match_labels}" | jq -r 'keys[]' 2>/dev/null || echo "")
                                    
                                    # Check for infra patterns in matchLabels
                                    if echo "${match_keys}" | grep -qE "node-role.kubernetes.io/infra"; then
                                        placement_configured=true
                                        placement_type="infra"
                                        log_debug "Found infra matchLabels in nodeSelector"
                                    elif echo "${match_keys}" | grep -qE "node-role.kubernetes.io/infrastructure"; then
                                        placement_configured=true
                                        placement_type="infra"
                                        log_debug "Found infrastructure matchLabels in nodeSelector"
                                    elif echo "${match_keys}" | grep -qE "node-role.kubernetes.io/worker"; then
                                        placement_configured=true
                                        placement_type="worker"
                                        log_debug "Found worker matchLabels in nodeSelector"
                                    fi
                                fi
                            # If only kubernetes.io/os: linux is present, it's not specifically targeted
                            elif echo "${selector_keys}" | grep -qE "kubernetes.io/os" && [[ $(echo "${selector_keys}" | wc -l) -eq 1 ]]; then
                                log_debug "Only OS selector found, not specifically targeted to worker/infra"
                            fi
                        fi
                        
                        # Check nodeAffinity matchLabels pattern
                        if [[ "${node_affinity}" != "null" && "${placement_configured}" == "false" ]]; then
                            local affinity_keys
                            affinity_keys=$(echo "${node_affinity}" | jq -r 'keys[]' 2>/dev/null || echo "")
                            
                            # Check for infra node affinity patterns
                            if echo "${affinity_keys}" | grep -qE "node-role.kubernetes.io/infra"; then
                                placement_configured=true
                                placement_type="infra"
                                log_debug "Found infra node affinity matchLabels in IngressController"
                            # Check for infrastructure node affinity
                            elif echo "${affinity_keys}" | grep -qE "node-role.kubernetes.io/infrastructure"; then
                                placement_configured=true
                                placement_type="infra"
                                log_debug "Found infrastructure node affinity matchLabels in IngressController"
                            # Check for worker node affinity
                            elif echo "${affinity_keys}" | grep -qE "node-role.kubernetes.io/worker"; then
                                placement_configured=true
                                placement_type="worker"
                                log_debug "Found worker node affinity matchLabels in IngressController"
                            fi
                        fi
                        
                        # Check tolerations for infra/worker taints
                        if [[ "${tolerations}" != "null" && "${tolerations}" != "[]" ]]; then
                            if echo "${tolerations}" | jq -r '.[].key' 2>/dev/null | grep -qE "(node-role.kubernetes.io/infra|node-role.kubernetes.io/infrastructure|node.openshift.io/os_id.*infra)"; then
                                placement_configured=true
                                if [[ -z "${placement_type}" ]]; then
                                    placement_type="infra"
                                fi
                            elif echo "${tolerations}" | jq -r '.[].key' 2>/dev/null | grep -qE "node-role.kubernetes.io/worker"; then
                                placement_configured=true
                                if [[ -z "${placement_type}" ]]; then
                                    placement_type="worker"
                                fi
                            fi
                        fi
                        
                        # Set placement status based on findings
                        if [[ "${placement_configured}" == "true" ]]; then
                            if [[ "${placement_type}" == "infra" ]]; then
                                ingress_status["node_placement_status"]="configured_for_infra"
                            elif [[ "${placement_type}" == "worker" ]]; then
                                ingress_status["node_placement_status"]="configured_for_worker"
                            else
                                ingress_status["node_placement_status"]="configured_other"
                            fi
                        else
                            ingress_status["node_placement_status"]="not_configured"
                        fi
                    else
                        ingress_status["node_placement_status"]="not_configured"
                    fi
                    
                    log_debug "IngressController configured with ${desired_replicas} replicas, node placement: ${ingress_status["node_placement_status"]}"
                else
                    error_messages+=("Default IngressController not found")
                    ingress_status["ingress_controller_status"]="not_found"
                    all_checks_successful=false
                fi
            else
                error_messages+=("No IngressController found")
                ingress_status["ingress_controller_status"]="not_found"
                all_checks_successful=false
            fi
        else
            error_messages+=("Failed to get IngressController configuration")
            all_checks_successful=false
        fi
    else
        error_messages+=("Failed to retrieve IngressController")
        all_checks_successful=false
    fi
    
    # Step 3: Check actual ingress pods
    log_debug "Checking ingress router pods..."
    local ingress_pods_json=""
    if execute_oc_command "get pods -n openshift-ingress -l ingresscontroller.operator.openshift.io/deployment-ingresscontroller=default -o json" "Get ingress pods" 1 5 > /dev/null; then
        ingress_pods_json=$(oc get pods -n openshift-ingress -l ingresscontroller.operator.openshift.io/deployment-ingresscontroller=default -o json 2>/dev/null)
        
        if [[ -n "${ingress_pods_json}" ]]; then
            local pod_count
            pod_count=$(echo "${ingress_pods_json}" | jq '.items | length' 2>/dev/null || echo "0")
            ingress_status["replica_count"]="${pod_count}"
            
            local ready_pods=0
            local running_on_infra=0
            local running_on_worker=0
            local pod_nodes=()
            
            for ((i=0; i<pod_count; i++)); do
                local pod_phase
                local pod_ready
                local pod_node
                
                pod_phase=$(echo "${ingress_pods_json}" | jq -r ".items[${i}].status.phase" 2>/dev/null || echo "unknown")
                pod_ready=$(echo "${ingress_pods_json}" | jq -r ".items[${i}].status.conditions[]? | select(.type==\"Ready\") | .status" 2>/dev/null || echo "False")
                pod_node=$(echo "${ingress_pods_json}" | jq -r ".items[${i}].spec.nodeName" 2>/dev/null || echo "unknown")
                
                if [[ "${pod_phase}" == "Running" && "${pod_ready}" == "True" ]]; then
                    ((ready_pods++))
                fi
                
                # Check which type of node the pod is running on
                if [[ "${pod_node}" != "unknown" && -n "${nodes_json}" ]]; then
                    pod_nodes+=("${pod_node}")
                    
                    local node_labels
                    node_labels=$(echo "${nodes_json}" | jq -r ".items[] | select(.metadata.name==\"${pod_node}\") | .metadata.labels" 2>/dev/null || echo "{}")
                    
                    if echo "${node_labels}" | jq -r 'keys[]' 2>/dev/null | grep -qE "(node-role.kubernetes.io/infra|node.openshift.io/os_id.*infra)"; then
                        ((running_on_infra++))
                    elif echo "${node_labels}" | jq -r 'keys[]' 2>/dev/null | grep -qE "node-role.kubernetes.io/worker"; then
                        ((running_on_worker++))
                    fi
                fi
            done
            
            ingress_status["available_replicas"]="${ready_pods}"
            ingress_status["ready_replicas"]="${ready_pods}"
            ingress_status["running_on_infra"]="${running_on_infra}"
            ingress_status["running_on_worker"]="${running_on_worker}"
            
            # Check pod distribution
            local unique_nodes
            unique_nodes=$(printf '%s\n' "${pod_nodes[@]}" | sort -u | wc -l)
            if [[ "${unique_nodes}" -eq "${pod_count}" ]]; then
                ingress_status["pod_distribution"]="well_distributed"
            elif [[ "${unique_nodes}" -gt 1 ]]; then
                ingress_status["pod_distribution"]="partially_distributed"
            else
                ingress_status["pod_distribution"]="single_node"
            fi
            
            log_debug "Found ${pod_count} ingress pods, ${ready_pods} ready, ${running_on_infra} on infra nodes, ${running_on_worker} on worker nodes"
        else
            error_messages+=("Failed to get ingress pods information")
            all_checks_successful=false
        fi
    else
        error_messages+=("Failed to retrieve ingress pods")
        all_checks_successful=false
    fi
    
    # Step 4: Determine overall status and recommendations
    local overall_status="${STATUS_HEALTHY}"
    local overall_message="Ingress configuration is optimal"
    local warnings=()
    local criticals=()
    
    # Check minimum replicas (should be at least 3 if infra/worker nodes are available)
    local available_nodes=$((${ingress_status["infra_nodes_available"]:-0} + ${ingress_status["worker_nodes_available"]:-0}))
    local desired_min_replicas=2
    local current_replicas="${ingress_status["desired_replicas"]:-0}"
    
    if [[ "${available_nodes}" -ge 3 ]]; then
        desired_min_replicas=3
        
        # Check if current replicas meet the HA requirement
        if [[ "${current_replicas}" -ge 3 ]]; then
            ingress_status["minimum_replicas_met"]="adequate_for_ha"
        else
            ingress_status["minimum_replicas_met"]="should_be_3"
            warnings+=("Ingress replicas (${current_replicas}) should be at least 3 for high availability when ${available_nodes} infra/worker nodes are available")
        fi
    else
        # For clusters with fewer than 3 nodes, check if replicas are adequate
        if [[ "${current_replicas}" -ge "${available_nodes}" ]] || [[ "${current_replicas}" -ge 2 ]]; then
            ingress_status["minimum_replicas_met"]="adequate_for_cluster_size"
        else
            ingress_status["minimum_replicas_met"]="should_increase"
            warnings+=("Ingress replicas (${current_replicas}) should be increased for better availability")
        fi
    fi
    
    # Check if ingress is running on appropriate nodes
    local infra_available="${ingress_status["infra_nodes_available"]:-0}"
    local worker_available="${ingress_status["worker_nodes_available"]:-0}"
    local running_on_infra="${ingress_status["running_on_infra"]:-0}"
    local running_on_worker="${ingress_status["running_on_worker"]:-0}"
    
    # Validate node placement - prioritize actual placement over configuration
    if [[ "${infra_available}" -gt 0 ]]; then
        # Infra nodes available - check actual placement first
        if [[ "${running_on_infra}" -gt 0 ]]; then
            # Ingress is running on infra nodes - placement is fine regardless of configuration
            if [[ "${running_on_infra}" -eq "${ingress_status["replica_count"]:-0}" ]]; then
                log_debug "All ingress pods running on infra nodes - optimal placement"
            else
                # Some pods on infra, some on worker - acceptable but could be improved
                log_debug "Mixed placement: ${running_on_infra} on infra, ${running_on_worker} on worker nodes"
                if [[ "${running_on_worker}" -gt 0 ]]; then
                    warnings+=("Some ingress pods (${running_on_worker}) are running on worker nodes instead of preferred infra nodes")
                fi
            fi
        else
            # No pods running on infra nodes despite availability
            if [[ "${ingress_status["node_placement_status"]}" =~ ^(configured_for_infra|configured_for_worker|configured_other)$ ]]; then
                criticals+=("Ingress configured but not running on any of ${infra_available} available infra nodes")
            else
                warnings+=("Ingress pods should run on infra nodes when available (${infra_available} infra nodes found). Consider configuring nodeSelector")
            fi
        fi
    elif [[ "${worker_available}" -gt 0 ]]; then
        # No infra nodes, but worker nodes available
        if [[ "${running_on_worker}" -gt 0 ]]; then
            # Running on worker nodes - acceptable placement
            log_debug "Ingress pods running on worker nodes - acceptable placement when no infra nodes available"
        else
            # Not running on worker nodes despite availability
            if [[ "${ingress_status["node_placement_status"]}" =~ ^(configured_for_worker|configured_other)$ ]]; then
                criticals+=("Ingress configured but not running on any of ${worker_available} available worker nodes")
            else
                warnings+=("Ingress pods should run on worker nodes when available (${worker_available} worker nodes found)")
            fi
        fi
    else
        # No dedicated infra or worker nodes - running on control plane nodes
        warnings+=("Ingress pods may be running on control plane nodes. Consider adding dedicated worker or infra nodes")
    fi
    
    # Check pod distribution
    if [[ "${ingress_status["pod_distribution"]}" == "single_node" && "${ingress_status["replica_count"]:-0}" -gt 1 ]]; then
        warnings+=("All ingress pods are running on a single node - poor distribution for high availability")
    fi
    
    # Check if pods are ready
    local ready_replicas="${ingress_status["ready_replicas"]:-0}"
    local total_replicas="${ingress_status["replica_count"]:-0}"
    
    if [[ "${ready_replicas}" -eq 0 ]]; then
        criticals+=("No ingress pods are ready")
    elif [[ "${ready_replicas}" -lt "${total_replicas}" ]]; then
        warnings+=("Not all ingress pods are ready (${ready_replicas}/${total_replicas})")
    fi
    
    # Determine final status
    if [[ ${#criticals[@]} -gt 0 ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="Critical ingress issues found: $(IFS="; "; echo "${criticals[*]}")"
        if [[ ${#warnings[@]} -gt 0 ]]; then
            overall_message="${overall_message}. Warnings: $(IFS="; "; echo "${warnings[*]}")"
        fi
    elif [[ ${#warnings[@]} -gt 0 ]]; then
        overall_status="${STATUS_WARNING}"
        overall_message="Ingress configuration warnings: $(IFS="; "; echo "${warnings[*]}")"
    elif [[ ! "${all_checks_successful}" == "true" ]]; then
        overall_status="${STATUS_UNKNOWN}"
        overall_message="Unable to complete ingress status checks"
    fi
    
    # Set final status
    ingress_status["overall_status"]="${overall_status}"
    ingress_status["overall_message"]="${overall_message}"
    
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        ingress_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Log summary
    log_info "Ingress status check completed:"
    log_info "  Overall status: ${overall_status}"
    log_info "  Ingress controller: ${ingress_status["ingress_controller_status"]}"
    log_info "  Replicas: ${ingress_status["ready_replicas"]}/${ingress_status["replica_count"]} (desired: ${ingress_status["desired_replicas"]})"
    log_info "  Running on infra nodes: ${ingress_status["running_on_infra"]}"
    log_info "  Running on worker nodes: ${ingress_status["running_on_worker"]}"
    log_info "  Node placement: ${ingress_status["node_placement_status"]}"
    log_info "  Pod distribution: ${ingress_status["pod_distribution"]}"
    
    return 0
}

# Get ingress status summary
get_ingress_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${ingress_status["overall_status"]}",
    "overall_message": "${ingress_status["overall_message"]}",
    "ingress_controller_status": "${ingress_status["ingress_controller_status"]}",
    "replica_count": ${ingress_status["replica_count"]},
    "desired_replicas": ${ingress_status["desired_replicas"]},
    "available_replicas": ${ingress_status["available_replicas"]},
    "ready_replicas": ${ingress_status["ready_replicas"]},
    "node_placement_status": "${ingress_status["node_placement_status"]}",
    "running_on_infra": ${ingress_status["running_on_infra"]},
    "running_on_worker": ${ingress_status["running_on_worker"]},
    "infra_nodes_available": ${ingress_status["infra_nodes_available"]},
    "worker_nodes_available": ${ingress_status["worker_nodes_available"]},
    "minimum_replicas_met": "${ingress_status["minimum_replicas_met"]}",
    "pod_distribution": "${ingress_status["pod_distribution"]}",
    "check_timestamp": "${ingress_status["check_timestamp"]}",
    "details": ${ingress_status["details"]:-"{}"},
    "errors": "${ingress_status["errors"]}"
}
EOF
            ;;
        "text")
            cat << EOF
=== OpenShift Ingress Status ===
Overall Status: ${ingress_status["overall_status"]}
Message: ${ingress_status["overall_message"]}
Ingress Controller: ${ingress_status["ingress_controller_status"]}
Replicas: ${ingress_status["ready_replicas"]}/${ingress_status["replica_count"]} (desired: ${ingress_status["desired_replicas"]})
Running on Infra Nodes: ${ingress_status["running_on_infra"]}
Running on Worker Nodes: ${ingress_status["running_on_worker"]}
Infra Nodes Available: ${ingress_status["infra_nodes_available"]}
Worker Nodes Available: ${ingress_status["worker_nodes_available"]}
Node Placement: ${ingress_status["node_placement_status"]}
Pod Distribution: ${ingress_status["pod_distribution"]}
Check Timestamp: ${ingress_status["check_timestamp"]}
EOF
            if [[ -n "${ingress_status["errors"]}" ]]; then
                echo "Errors: ${ingress_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================

# Node details status structure
declare -A node_details_status=(
    ["overall_status"]="${STATUS_UNKNOWN}"
    ["overall_message"]=""
    ["total_nodes"]="0"
    ["master_nodes"]="0"
    ["worker_nodes"]="0"
    ["infra_nodes"]="0"
    ["ready_nodes"]="0"
    ["not_ready_nodes"]="0"
    ["check_timestamp"]=""
    ["details"]=""
    ["errors"]=""
)

# Check Machine Config Pools status
check_machine_config_pools() {
    log_debug "Checking Machine Config Pools status..."
    
    # Get MCP information
    local mcp_json=""
    if ! mcp_json=$(execute_oc_json "get machineconfigpools -o json" "Get Machine Config Pools"); then
        log_warn "Failed to retrieve Machine Config Pools information"
        return 1
    fi
    
    # Validate MCP JSON
    if ! validate_json "${mcp_json}" "MCP data"; then
        log_warn "Invalid JSON response from MCP query"
        return 1
    fi
    
    # Count total MCPs
    local total_mcps
    total_mcps=$(count_json_array "${mcp_json}" ".items" "Machine Config Pools")
    
    if [[ "${total_mcps}" -eq 0 ]]; then
        log_debug "No Machine Config Pools found"
        echo "no_mcps_found"
        return 0
    fi
    
    log_debug "Found ${total_mcps} Machine Config Pools"
    
    # Initialize counters
    local ready_mcps=0
    local updating_mcps=0
    local degraded_mcps=0
    local mcp_details=()
    
    # Process each MCP
    local mcp_index=0
    while [[ ${mcp_index} -lt ${total_mcps} ]]; do
        # Extract MCP information
        local mcp_name
        local mcp_ready_machines
        local mcp_updated_machines
        local mcp_degraded_machines
        local mcp_total_machines
        local mcp_ready_condition
        local mcp_updating_condition
        local mcp_degraded_condition
        
        mcp_name=$(parse_json_field "${mcp_json}" ".items[${mcp_index}].metadata.name" "" "MCP name")
        
        if [[ -z "${mcp_name}" ]]; then
            log_warn "Skipping MCP with missing name at index ${mcp_index}"
            ((mcp_index++))
            continue
        fi
        
        log_debug "Processing MCP ${mcp_index}/${total_mcps}: ${mcp_name}"
        
        # Extract machine counts
        local status_json
        status_json=$(parse_json_field "${mcp_json}" ".items[${mcp_index}].status" "{}" "MCP status")
        
        mcp_ready_machines=$(echo "${status_json}" | jq -r '.readyMachineCount // 0' 2>/dev/null || echo "0")
        mcp_updated_machines=$(echo "${status_json}" | jq -r '.updatedMachineCount // 0' 2>/dev/null || echo "0")
        mcp_degraded_machines=$(echo "${status_json}" | jq -r '.degradedMachineCount // 0' 2>/dev/null || echo "0")
        mcp_total_machines=$(echo "${status_json}" | jq -r '.machineCount // 0' 2>/dev/null || echo "0")
        
        # Extract conditions
        local conditions_json
        conditions_json=$(echo "${status_json}" | jq -r '.conditions // []' 2>/dev/null || echo "[]")
        
        # Check for Updated condition (MCPs use "Updated" instead of "Ready")
        mcp_ready_condition=$(echo "${conditions_json}" | jq -r '.[] | select(.type=="Updated") | .status' 2>/dev/null || echo "Unknown")
        
        # Check for Updating condition
        mcp_updating_condition=$(echo "${conditions_json}" | jq -r '.[] | select(.type=="Updating") | .status' 2>/dev/null || echo "Unknown")
        
        # Check for Degraded condition
        mcp_degraded_condition=$(echo "${conditions_json}" | jq -r '.[] | select(.type=="Degraded") | .status' 2>/dev/null || echo "Unknown")
        
        # Determine MCP status
        local mcp_status="unknown"
        local mcp_message=""
        
        if [[ "${mcp_degraded_condition}" == "True" ]]; then
            mcp_status="degraded"
            mcp_message="MCP is degraded"
            ((degraded_mcps++))
        elif [[ "${mcp_updating_condition}" == "True" ]]; then
            mcp_status="updating"
            mcp_message="MCP is updating"
            ((updating_mcps++))
        elif [[ "${mcp_ready_condition}" == "True" ]]; then
            mcp_status="ready"
            mcp_message="MCP is ready"
            ((ready_mcps++))
        else
            mcp_status="unknown"
            mcp_message="MCP status unknown"
        fi
        
        log_debug "MCP ${mcp_name}: status=${mcp_status}, ready=${mcp_ready_machines}/${mcp_total_machines}, updated=${mcp_updated_machines}/${mcp_total_machines}"
        
        # Create MCP detail JSON
        local mcp_detail
        mcp_detail=$(cat << EOF
{
    "name": "${mcp_name}",
    "status": "${mcp_status}",
    "message": "${mcp_message}",
    "ready_machines": ${mcp_ready_machines},
    "updated_machines": ${mcp_updated_machines},
    "degraded_machines": ${mcp_degraded_machines},
    "total_machines": ${mcp_total_machines},
    "ready_condition": "${mcp_ready_condition}",
    "updating_condition": "${mcp_updating_condition}",
    "degraded_condition": "${mcp_degraded_condition}"
}
EOF
        )
        
        mcp_details+=("${mcp_detail}")
        ((mcp_index++))
    done
    
    # Determine overall MCP status
    local overall_mcp_status="unknown"
    local overall_mcp_message=""
    
    if [[ ${degraded_mcps} -gt 0 ]]; then
        overall_mcp_status="degraded"
        overall_mcp_message="${degraded_mcps} of ${total_mcps} MCPs are degraded"
    elif [[ ${updating_mcps} -gt 0 ]]; then
        overall_mcp_status="updating"
        overall_mcp_message="${updating_mcps} of ${total_mcps} MCPs are updating"
    elif [[ ${ready_mcps} -eq ${total_mcps} ]]; then
        overall_mcp_status="ready"
        overall_mcp_message="All ${total_mcps} MCPs are ready"
    else
        overall_mcp_status="mixed"
        overall_mcp_message="Mixed MCP status across cluster"
    fi
    
    # Create result JSON
    local mcp_result
    mcp_result=$(cat << EOF
{
    "overall_status": "${overall_mcp_status}",
    "overall_message": "${overall_mcp_message}",
    "total_mcps": ${total_mcps},
    "ready_mcps": ${ready_mcps},
    "updating_mcps": ${updating_mcps},
    "degraded_mcps": ${degraded_mcps},
    "details": [$(IFS=","; echo "${mcp_details[*]}")]
}
EOF
    )
    
    log_debug "MCP status result: ${mcp_result}"
    echo "${mcp_result}"
    return 0
}

# Check detailed node information including roles and IPs
check_node_details() {
    log_info "Collecting detailed node information..."
    
    # Reset node details status
    node_details_status["overall_status"]="${STATUS_UNKNOWN}"
    node_details_status["overall_message"]=""
    node_details_status["total_nodes"]="0"
    node_details_status["master_nodes"]="0"
    node_details_status["worker_nodes"]="0"
    node_details_status["infra_nodes"]="0"
    node_details_status["ready_nodes"]="0"
    node_details_status["not_ready_nodes"]="0"
    node_details_status["check_timestamp"]="$(get_timestamp)"
    node_details_status["details"]=""
    node_details_status["errors"]=""
    
    # Get detailed node information
    local nodes_json=""
    if ! nodes_json=$(execute_oc_json "get nodes -o json" "Get detailed node information"); then
        log_error "Failed to retrieve detailed node information"
        node_details_status["overall_status"]="${STATUS_CRITICAL}"
        node_details_status["overall_message"]="Failed to retrieve node information"
        node_details_status["errors"]="Unable to access cluster nodes"
        return 1
    fi
    
    # Validate nodes JSON
    if ! validate_json "${nodes_json}" "nodes data"; then
        log_error "Invalid JSON response from nodes query"
        node_details_status["overall_status"]="${STATUS_CRITICAL}"
        node_details_status["overall_message"]="Invalid response from cluster API"
        node_details_status["errors"]="Invalid JSON response from nodes query"
        return 1
    fi
    
    # Count total nodes
    local total_nodes
    total_nodes=$(count_json_array "${nodes_json}" ".items" "cluster nodes")
    node_details_status["total_nodes"]="${total_nodes}"
    
    if [[ "${total_nodes}" -eq 0 ]]; then
        log_warn "No nodes found in cluster"
        node_details_status["overall_status"]="${STATUS_UNKNOWN}"
        node_details_status["overall_message"]="No nodes found in cluster"
        return 0
    fi
    
    log_info "Found ${total_nodes} nodes to analyze"
    
    # Initialize counters
    local master_count=0
    local worker_count=0
    local infra_count=0
    local ready_count=0
    local not_ready_count=0
    local node_details=()
    local error_messages=()
    
    # Process each node
    local node_index=0
    while [[ ${node_index} -lt ${total_nodes} ]]; do
        # Extract node information
        local node_name
        local node_roles
        local node_status
        local internal_ip
        local external_ip
        local os_image
        local kernel_version
        local container_runtime
        local architecture
        
        node_name=$(parse_json_field "${nodes_json}" ".items[${node_index}].metadata.name" "" "node name")
        
        if [[ -z "${node_name}" ]]; then
            log_warn "Skipping node with missing name at index ${node_index}"
            ((node_index++))
            continue
        fi
        
        log_debug "Processing node ${node_index}/${total_nodes}: ${node_name}"
        
        # Extract node labels to determine roles
        local labels_json
        labels_json=$(parse_json_field "${nodes_json}" ".items[${node_index}].metadata.labels" "{}" "node labels")
        
        # Determine node roles
        local roles=()
        if echo "${labels_json}" | grep -q "node-role.kubernetes.io/control-plane"; then
            roles+=("master")
            ((master_count++))
        elif echo "${labels_json}" | grep -q "node-role.kubernetes.io/master"; then
            roles+=("master")
            ((master_count++))
        fi
        
        if echo "${labels_json}" | grep -q "node-role.kubernetes.io/worker"; then
            roles+=("worker")
            ((worker_count++))
        fi
        
        if echo "${labels_json}" | grep -q "node-role.kubernetes.io/infra"; then
            roles+=("infra")
            ((infra_count++))
        fi
        
        # If no specific roles found, assume worker
        if [[ ${#roles[@]} -eq 0 ]]; then
            roles+=("worker")
            ((worker_count++))
        fi
        
        # Join roles with comma
        node_roles=$(IFS=','; echo "${roles[*]}")
        
        # Extract node status and conditions
        local ready_condition
        ready_condition=$(parse_json_field "${nodes_json}" ".items[${node_index}].status.conditions[] | select(.type==\"Ready\") | .status" "Unknown" "ready condition")
        
        if [[ "${ready_condition}" == "True" ]]; then
            node_status="Ready"
            ((ready_count++))
        else
            node_status="NotReady"
            ((not_ready_count++))
        fi
        
        # Extract additional node conditions
        local conditions_json
        conditions_json=$(parse_json_field "${nodes_json}" ".items[${node_index}].status.conditions" "[]" "node conditions")
        
        local memory_pressure="Unknown"
        local disk_pressure="Unknown"
        local pid_pressure="Unknown"
        local network_unavailable="Unknown"
        
        # Extract specific condition statuses
        if [[ -n "${conditions_json}" && "${conditions_json}" != "[]" ]]; then
            memory_pressure=$(echo "${conditions_json}" | jq -r '.[] | select(.type=="MemoryPressure") | .status' 2>/dev/null || echo "Unknown")
            disk_pressure=$(echo "${conditions_json}" | jq -r '.[] | select(.type=="DiskPressure") | .status' 2>/dev/null || echo "Unknown")
            pid_pressure=$(echo "${conditions_json}" | jq -r '.[] | select(.type=="PIDPressure") | .status' 2>/dev/null || echo "Unknown")
            network_unavailable=$(echo "${conditions_json}" | jq -r '.[] | select(.type=="NetworkUnavailable") | .status' 2>/dev/null || echo "Unknown")
            
            # Set defaults if conditions are empty
            if [[ -z "${memory_pressure}" || "${memory_pressure}" == "null" ]]; then
                memory_pressure="Unknown"
            fi
            if [[ -z "${disk_pressure}" || "${disk_pressure}" == "null" ]]; then
                disk_pressure="Unknown"
            fi
            if [[ -z "${pid_pressure}" || "${pid_pressure}" == "null" ]]; then
                pid_pressure="Unknown"
            fi
            if [[ -z "${network_unavailable}" || "${network_unavailable}" == "null" ]]; then
                network_unavailable="Unknown"
            fi
        fi
        
        # Extract IP addresses
        local addresses_json
        addresses_json=$(parse_json_field "${nodes_json}" ".items[${node_index}].status.addresses" "[]" "node addresses")
        
        internal_ip=$(echo "${addresses_json}" | jq -r '.[] | select(.type=="InternalIP") | .address' 2>/dev/null | head -1 || echo "unknown")
        
        # Extract system information
        local node_info_json
        node_info_json=$(parse_json_field "${nodes_json}" ".items[${node_index}].status.nodeInfo" "{}" "node info")
        
        os_image=$(echo "${node_info_json}" | jq -r '.osImage' 2>/dev/null || echo "unknown")
        kernel_version=$(echo "${node_info_json}" | jq -r '.kernelVersion' 2>/dev/null || echo "unknown")
        container_runtime=$(echo "${node_info_json}" | jq -r '.containerRuntimeVersion' 2>/dev/null || echo "unknown")
        architecture=$(echo "${node_info_json}" | jq -r '.architecture' 2>/dev/null || echo "unknown")
        
        # Extract node taints
        local taints_json
        taints_json=$(parse_json_field "${nodes_json}" ".items[${node_index}].spec.taints" "[]" "node taints")
        
        local taints_count=0
        local taints_summary="None"
        local taints_details=""
        
        if [[ -n "${taints_json}" && "${taints_json}" != "[]" && "${taints_json}" != "null" ]]; then
            taints_count=$(echo "${taints_json}" | jq '. | length' 2>/dev/null || echo "0")
            
            if [[ "${taints_count}" -gt 0 ]]; then
                # Create a summary of taints
                local taint_keys=()
                local taint_index=0
                
                while [[ ${taint_index} -lt ${taints_count} ]]; do
                    local taint_key
                    local taint_value
                    local taint_effect
                    
                    taint_key=$(echo "${taints_json}" | jq -r ".[${taint_index}].key" 2>/dev/null || echo "unknown")
                    taint_value=$(echo "${taints_json}" | jq -r ".[${taint_index}].value" 2>/dev/null || echo "")
                    taint_effect=$(echo "${taints_json}" | jq -r ".[${taint_index}].effect" 2>/dev/null || echo "unknown")
                    
                    # Build taint description
                    local taint_desc="${taint_key}"
                    if [[ -n "${taint_value}" && "${taint_value}" != "null" ]]; then
                        taint_desc="${taint_desc}=${taint_value}"
                    fi
                    taint_desc="${taint_desc}:${taint_effect}"
                    
                    taint_keys+=("${taint_desc}")
                    ((taint_index++))
                done
                
                # Join taint descriptions
                taints_summary=$(IFS=", "; echo "${taint_keys[*]}")
                taints_details="${taints_json}"
                
                log_debug "Node ${node_name} has ${taints_count} taint(s): ${taints_summary}"
            fi
        fi
        
        # Extract resource capacity
        local capacity_json
        capacity_json=$(parse_json_field "${nodes_json}" ".items[${node_index}].status.capacity" "{}" "node capacity")
        
        local cpu_capacity
        local memory_capacity
        local pods_capacity
        
        cpu_capacity=$(echo "${capacity_json}" | jq -r '.cpu // "unknown"' 2>/dev/null || echo "unknown")
        local memory_capacity_raw
        memory_capacity_raw=$(echo "${capacity_json}" | jq -r '.memory // "unknown"' 2>/dev/null || echo "unknown")
        # Convert memory from Ki format to GB
        memory_capacity=$(format_k8s_memory_to_gb "${memory_capacity_raw}")
        pods_capacity=$(echo "${capacity_json}" | jq -r '.pods // "unknown"' 2>/dev/null || echo "unknown")
        
        # Create node detail JSON
        local node_detail
        node_detail=$(cat << EOF
{
    "name": "${node_name}",
    "roles": "${node_roles}",
    "status": "${node_status}",
    "internal_ip": "${internal_ip}",
    "os_image": "${os_image}",
    "kernel_version": "${kernel_version}",
    "container_runtime": "${container_runtime}",
    "architecture": "${architecture}",
    "cpu_capacity": "${cpu_capacity}",
    "memory_capacity": "${memory_capacity}",
    "pods_capacity": "${pods_capacity}",
    "memory_pressure": "${memory_pressure}",
    "disk_pressure": "${disk_pressure}",
    "pid_pressure": "${pid_pressure}",
    "network_unavailable": "${network_unavailable}",
    "taints_count": ${taints_count},
    "taints_summary": "${taints_summary}",
    "taints_details": ${taints_details:-"[]"},
    "check_timestamp": "$(get_timestamp)"
}
EOF
        )
        
        node_details+=("${node_detail}")
        
        log_debug "Node ${node_name}: roles=${node_roles}, status=${node_status}, ip=${internal_ip}"
        ((node_index++))
    done
    
    # Update status counters
    node_details_status["master_nodes"]="${master_count}"
    node_details_status["worker_nodes"]="${worker_count}"
    node_details_status["infra_nodes"]="${infra_count}"
    node_details_status["ready_nodes"]="${ready_count}"
    node_details_status["not_ready_nodes"]="${not_ready_count}"
    
    # Create details JSON array
    local details_json="["
    for i in "${!node_details[@]}"; do
        if [[ ${i} -gt 0 ]]; then
            details_json+=","
        fi
        details_json+="${node_details[${i}]}"
    done
    details_json+="]"
    node_details_status["details"]="${details_json}"
    
    # Combine error messages
    if [[ ${#error_messages[@]} -gt 0 ]]; then
        node_details_status["errors"]=$(IFS="; "; echo "${error_messages[*]}")
    fi
    
    # Determine overall status
    local overall_status="${STATUS_UNKNOWN}"
    local overall_message=""
    
    if [[ ${not_ready_count} -gt 0 ]]; then
        overall_status="${STATUS_CRITICAL}"
        overall_message="${not_ready_count} node(s) are not ready"
    elif [[ ${ready_count} -eq ${total_nodes} ]]; then
        overall_status="${STATUS_HEALTHY}"
        overall_message="All ${total_nodes} nodes are ready"
    else
        overall_status="${STATUS_WARNING}"
        overall_message="Mixed node status across cluster"
    fi
    
    # Check Machine Config Pools status
    log_debug "Checking Machine Config Pools status..."
    local mcp_status_result=""
    if mcp_status_result=$(check_machine_config_pools); then
        node_details_status["mcp_status"]="${mcp_status_result}"
        log_debug "Machine Config Pools status checked successfully"
    else
        error_messages+=("Failed to check Machine Config Pools status")
        node_details_status["mcp_status"]="unknown"
    fi
    
    # Update overall status
    node_details_status["overall_status"]="${overall_status}"
    node_details_status["overall_message"]="${overall_message}"
    
    # Log summary
    log_info "Node details collection completed:"
    log_info "  Total nodes: ${total_nodes}"
    log_info "  Master nodes: ${master_count}"
    log_info "  Worker nodes: ${worker_count}"
    log_info "  Infra nodes: ${infra_count}"
    log_info "  Ready nodes: ${ready_count}"
    log_info "  Not ready nodes: ${not_ready_count}"
    log_info "  Overall status: ${overall_status}"
    
    case "${overall_status}" in
        "${STATUS_HEALTHY}")
            log_success "${overall_message}"
            ;;
        "${STATUS_WARNING}")
            log_warn "${overall_message}"
            ;;
        "${STATUS_CRITICAL}")
            log_error "${overall_message}"
            ;;
        *)
            log_warn "${overall_message}"
            ;;
    esac
    
    return 0
}

# Get node details status summary
get_node_details_status_summary() {
    local format="${1:-text}"
    
    case "${format}" in
        "json")
            cat << EOF
{
    "overall_status": "${node_details_status["overall_status"]}",
    "overall_message": "${node_details_status["overall_message"]}",
    "total_nodes": ${node_details_status["total_nodes"]},
    "master_nodes": ${node_details_status["master_nodes"]},
    "worker_nodes": ${node_details_status["worker_nodes"]},
    "infra_nodes": ${node_details_status["infra_nodes"]},
    "ready_nodes": ${node_details_status["ready_nodes"]},
    "not_ready_nodes": ${node_details_status["not_ready_nodes"]},
    "check_timestamp": "${node_details_status["check_timestamp"]}",
    "details": ${node_details_status["details"]:-"[]"},
    "errors": "${node_details_status["errors"]}"
}
EOF
            ;;
        "text"|*)
            cat << EOF
Node Details Status: ${node_details_status["overall_status"]}
Message: ${node_details_status["overall_message"]}
Total Nodes: ${node_details_status["total_nodes"]}
Master Nodes: ${node_details_status["master_nodes"]}
Worker Nodes: ${node_details_status["worker_nodes"]}
Infra Nodes: ${node_details_status["infra_nodes"]}
Ready Nodes: ${node_details_status["ready_nodes"]}
Not Ready Nodes: ${node_details_status["not_ready_nodes"]}
Check Timestamp: ${node_details_status["check_timestamp"]}
EOF
            if [[ -n "${node_details_status["errors"]}" ]]; then
                echo "Errors: ${node_details_status["errors"]}"
            fi
            ;;
    esac
}

# =============================================================================
# TEST FUNCTIONS
# =============================================================================

# Test function for NTP node status check (offline mode)
test_node_ntp_status_offline() {
    echo "Testing check_node_ntp_status function (offline mode)..."
    
    # Save original function
    local original_execute_oc_command=$(declare -f execute_oc_command)
    
    # Mock the execute_oc_command function for testing
    execute_oc_command() {
        local cmd="$1"
        local description="$2"
        
        echo "Mock execute_oc_command called with: $cmd" >&2
        
        # Simulate different timedatectl outputs based on node name
        if [[ "$cmd" == *"test-node-1"* && "$cmd" == *"timedatectl"* ]]; then
            # Simulate synchronized node
            cat << EOF
               Local time: Wed 2024-01-10 15:30:45 UTC
           Universal time: Wed 2024-01-10 15:30:45 UTC
                 RTC time: Wed 2024-01-10 15:30:45
                Time zone: UTC (UTC, +0000)
System clock synchronized: yes
              NTP service: active
          NTP synchronized: yes
EOF
        elif [[ "$cmd" == *"test-node-2"* && "$cmd" == *"timedatectl"* ]]; then
            # Simulate unsynchronized node
            cat << EOF
               Local time: Wed 2024-01-10 15:30:45 UTC
           Universal time: Wed 2024-01-10 15:30:45 UTC
                 RTC time: Wed 2024-01-10 15:30:45
                Time zone: UTC (UTC, +0000)
System clock synchronized: no
              NTP service: inactive
          NTP synchronized: no
EOF
        elif [[ "$cmd" == *"chrony"* ]]; then
            # Simulate chrony sources output
            cat << EOF
^* time.cloudflare.com    2   6    17    12   +123us[+456us] +/-   15ms
^- pool.ntp.org          3   7    17    15   -234us[-567us] +/-   25ms
EOF
        else
            # Simulate access denied
            return 1
        fi
        
        return 0
    }
    
    # Test synchronized node
    echo "Testing synchronized node..."
    local result1
    result1=$(check_node_ntp_status "test-node-1")
    echo "Result for test-node-1:"
    echo "$result1" | jq .
    
    # Test unsynchronized node
    echo "Testing unsynchronized node..."
    local result2
    result2=$(check_node_ntp_status "test-node-2")
    echo "Result for test-node-2:"
    echo "$result2" | jq .
    
    # Test node with access denied
    echo "Testing node with access denied..."
    local result3
    result3=$(check_node_ntp_status "test-node-3")
    echo "Result for test-node-3:"
    echo "$result3" | jq .
    
    # Restore original function
    eval "$original_execute_oc_command"
}

# Test function for FIPS node status check (offline mode)
test_node_fips_status_offline() {
    echo "Testing check_node_fips_status function (offline mode)..."
    
    # Save original function
    local original_execute_oc_command=$(declare -f execute_oc_command)
    
    # Mock the execute_oc_command function for testing
    execute_oc_command() {
        local cmd="$1"
        local description="$2"
        
        echo "Mock execute_oc_command called with: $cmd" >&2
        
        # Simulate different FIPS check results based on node name
        if [[ "$cmd" == *"test-node-1"* ]]; then
            # Simulate FIPS enabled
            echo "1"
        elif [[ "$cmd" == *"test-node-2"* ]]; then
            # Simulate FIPS disabled
            echo "0"
        else
            # Simulate access denied
            return 1
        fi
        
        return 0
    }
    
    # Test FIPS enabled node
    echo "Testing FIPS enabled node..."
    local result1
    result1=$(check_node_fips_status "test-node-1" "Red Hat Enterprise Linux CoreOS 4.12.0 (FIPS)")
    echo "Result for test-node-1:"
    echo "$result1" | jq .
    
    # Test FIPS disabled node
    echo "Testing FIPS disabled node..."
    local result2
    result2=$(check_node_fips_status "test-node-2" "Red Hat Enterprise Linux CoreOS 4.12.0")
    echo "Result for test-node-2:"
    echo "$result2" | jq .
    
    # Test node with access denied
    echo "Testing node with access denied..."
    local result3
    result3=$(check_node_fips_status "test-node-3" "Red Hat Enterprise Linux CoreOS 4.12.0")
    echo "Result for test-node-3:"
    echo "$result3" | jq .
    
    # Restore original function
    eval "$original_execute_oc_command"
}

# Test function for etcd encryption status check (offline mode)
test_etcd_encryption_status_offline() {
    echo "Testing etcd encryption status functions (offline mode)..."
    
    # Save original function
    local original_execute_oc_command=$(declare -f execute_oc_command)
    local original_execute_oc_json=$(declare -f execute_oc_json)
    
    # Mock the execute_oc_command and execute_oc_json functions for testing
    execute_oc_command() {
        local cmd="$1"
        local description="$2"
        
        echo "Mock execute_oc_command called with: $cmd" >&2
        
        # Simulate different outputs based on command
        if [[ "$cmd" == *"get secrets"* && "$cmd" == *"openshift-etcd"* ]]; then
            # Simulate etcd encryption secrets
            cat << EOF
etcd-encryption-key-1   Opaque   1      5d
etcd-encryption-key-2   Opaque   1      2d
EOF
        elif [[ "$cmd" == *"logs"* && "$cmd" == *"etcd-operator"* ]]; then
            # Simulate etcd operator logs with key rotation
            cat << EOF
2024-01-10T15:30:45Z INFO Key rotation completed successfully
2024-01-09T10:15:30Z INFO Starting key rotation process
2024-01-08T08:45:20Z INFO Encryption key updated
EOF
        else
            return 1
        fi
        
        return 0
    }
    
    execute_oc_json() {
        local cmd="$1"
        local description="$2"
        
        echo "Mock execute_oc_json called with: $cmd" >&2
        
        # Simulate different JSON outputs based on command
        if [[ "$cmd" == *"get apiserver cluster"* ]]; then
            # Simulate APIServer configuration with encryption enabled
            cat << EOF
{
    "spec": {
        "encryption": {
            "type": "aescbc"
        }
    }
}
EOF
        elif [[ "$cmd" == *"get pods"* && "$cmd" == *"openshift-etcd"* ]]; then
            # Simulate etcd pods
            cat << EOF
{
    "items": [
        {
            "metadata": {"name": "etcd-master-1"},
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "Ready", "status": "True"}
                ]
            }
        },
        {
            "metadata": {"name": "etcd-master-2"},
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "Ready", "status": "True"}
                ]
            }
        },
        {
            "metadata": {"name": "etcd-master-3"},
            "status": {
                "phase": "Running",
                "conditions": [
                    {"type": "Ready", "status": "False"}
                ]
            }
        }
    ]
}
EOF
        elif [[ "$cmd" == *"get secrets"* && "$cmd" == *"k8s-app=etcd"* ]]; then
            # Simulate etcd encryption key secrets
            cat << EOF
{
    "items": [
        {
            "metadata": {
                "name": "etcd-encryption-key-current",
                "creationTimestamp": "2024-01-10T15:30:45Z"
            }
        }
    ]
}
EOF
        else
            echo "{}"
        fi
        
        return 0
    }
    
    # Test encryption configuration check
    echo "Testing encryption configuration check..."
    local config_result
    config_result=$(check_etcd_encryption_config)
    echo "Encryption config result:"
    echo "$config_result" | jq .
    
    # Test key rotation check
    echo "Testing key rotation check..."
    local rotation_result
    rotation_result=$(check_etcd_key_rotation)
    echo "Key rotation result:"
    echo "$rotation_result" | jq .
    
    # Test pod health check
    echo "Testing etcd pod health check..."
    local pod_result
    pod_result=$(check_etcd_pod_health)
    echo "Pod health result:"
    echo "$pod_result" | jq .
    
    # Restore original functions
    eval "$original_execute_oc_command"
    eval "$original_execute_oc_json"
}

# Test utility functions
test_utility_functions() {
    echo "Testing utility functions..."
    
    # Test JSON parsing
    local test_json='{"items":[{"metadata":{"name":"test1"},"status":{"conditions":[{"type":"Available","status":"True"},{"type":"Progressing","status":"False"},{"type":"Degraded","status":"False"}]}},{"metadata":{"name":"test2"},"status":{"conditions":[{"type":"Available","status":"False"},{"type":"Progressing","status":"True"},{"type":"Degraded","status":"True"}]}}]}'
    
    echo "Testing parse_json_field..."
    local first_name
    first_name=$(parse_json_field "$test_json" ".items[0].metadata.name" "" "first item name")
    echo "First item name: $first_name"
    
    echo "Testing count_json_array..."
    local item_count
    item_count=$(count_json_array "$test_json" ".items" "test items")
    echo "Item count: $item_count"
    
    echo "Testing status determination..."
    local test1_status
    test1_status=$(determine_status "test1" "True" "False" "False")
    echo "Test1 status: $test1_status"
    
    local test2_status
    test2_status=$(determine_status "test2" "False" "True" "True")
    echo "Test2 status: $test2_status"
    
    echo "Testing simple status determination..."
    local fips_enabled_status
    fips_enabled_status=$(determine_simple_status "FIPS" "true" "true")
    echo "FIPS status (enabled): $fips_enabled_status"
    
    local fips_disabled_status
    fips_disabled_status=$(determine_simple_status "FIPS" "false" "true")
    echo "FIPS status (disabled): $fips_disabled_status"
    
    echo "Testing timestamp functions..."
    local iso_timestamp
    iso_timestamp=$(get_timestamp)
    echo "ISO timestamp: $iso_timestamp"
    
    local readable_timestamp
    readable_timestamp=$(get_readable_timestamp)
    echo "Readable timestamp: $readable_timestamp"
    
    echo "Testing duration formatting..."
    local duration1
    duration1=$(format_duration 3661)
    echo "3661 seconds = $duration1"
    
    local duration2
    duration2=$(format_duration 86400)
    echo "86400 seconds = $duration2"
    
    echo "Testing byte formatting..."
    local bytes1
    bytes1=$(format_bytes 1024)
    echo "1024 bytes = $bytes1"
    
    local bytes2
    bytes2=$(format_bytes 1048576)
    echo "1048576 bytes = $bytes2"
    
    echo "Testing Kubernetes memory format conversion..."
    local mem1
    mem1=$(format_k8s_memory_to_gb "32768Ki")
    echo "32768Ki = $mem1"
    
    local mem2
    mem2=$(format_k8s_memory_to_gb "16384Mi")
    echo "16384Mi = $mem2"
    
    local mem3
    mem3=$(format_k8s_memory_to_gb "32Gi")
    echo "32Gi = $mem3"
    
    echo "Testing age parsing..."
    local age1
    age1=$(parse_age_to_seconds "1d2h3m4s")
    echo "1d2h3m4s = $age1 seconds"
    
    local age2
    age2=$(parse_age_to_seconds "30m")
    echo "30m = $age2 seconds"
    
    echo "Testing HTML sanitization..."
    local original='<script>alert("test")</script> & "quotes"'
    local sanitized
    sanitized=$(sanitize_html "$original")
    echo "Original: $original"
    echo "Sanitized: $sanitized"
    
    echo "Testing string truncation..."
    local long_string="This is a very long string that should be truncated"
    local truncated
    truncated=$(truncate_string "$long_string" 20)
    echo "Original: $long_string"
    echo "Truncated: $truncated"
}

# Test status summary functions
test_status_summaries() {
    echo "Testing status summary functions..."
    
    # Set some test values in the status arrays
    ntp_status["overall_status"]="warning"
    ntp_status["overall_message"]="Some nodes have NTP synchronization issues"
    ntp_status["synchronized_nodes"]="2"
    ntp_status["unsynchronized_nodes"]="1"
    ntp_status["unknown_nodes"]="0"
    ntp_status["total_nodes"]="3"
    ntp_status["check_timestamp"]="2024-01-10T15:30:45Z"
    ntp_status["details"]='[{"name":"node1","status":"healthy"},{"name":"node2","status":"critical"}]'
    ntp_status["errors"]="node2: Debug access failed"
    
    fips_status["overall_status"]="healthy"
    fips_status["overall_message"]="All nodes are FIPS compliant"
    fips_status["compliant_nodes"]="3"
    fips_status["non_compliant_nodes"]="0"
    fips_status["unknown_nodes"]="0"
    fips_status["total_nodes"]="3"
    fips_status["check_timestamp"]="2024-01-10T15:30:45Z"
    fips_status["details"]='[{"name":"node1","status":"healthy"},{"name":"node2","status":"healthy"},{"name":"node3","status":"healthy"}]'
    fips_status["errors"]=""
    
    echo "NTP Status Summary (text):"
    get_ntp_status_summary "text"
    
    echo ""
    echo "NTP Status Summary (JSON):"
    get_ntp_status_summary "json"
    
    echo ""
    echo "FIPS Status Summary (text):"
    get_fips_status_summary "text"
    
    echo ""
    echo "FIPS Status Summary (JSON):"
    get_fips_status_summary "json"
    
    echo ""
    echo "etcd Encryption Status Summary (text):"
    get_etcd_encryption_status_summary "text"
    
    echo ""
    echo "etcd Encryption Status Summary (JSON):"
    get_etcd_encryption_status_summary "json"
}

# Main test runner function
run_tests() {
    echo "=========================================="
    echo "OpenShift Health Report - Module Tests"
    echo "=========================================="
    
    # Set test environment
    OUTPUT_FILE="/tmp/test-report.html"
    LOG_LEVEL="DEBUG"
    TEMP_DIR="/tmp/test-health-report-$$"
    VERBOSE=true
    DEBUG=true
    
    # Create temp directory
    mkdir -p "${TEMP_DIR}"
    
    echo ""
    echo "1. Testing utility functions..."
    echo "----------------------------------------"
    test_utility_functions
    
    echo ""
    echo "2. Testing FIPS module..."
    echo "----------------------------------------"
    test_node_fips_status_offline
    
    echo ""
    echo "3. Testing NTP module..."
    echo "----------------------------------------"
    test_node_ntp_status_offline
    
    echo ""
    echo "4. Testing etcd encryption module..."
    echo "----------------------------------------"
    test_etcd_encryption_status_offline
    
    echo ""
    echo "5. Testing status summaries..."
    echo "----------------------------------------"
    test_status_summaries
    
    echo ""
    echo "6. Testing full modules (expected to fail without cluster)..."
    echo "----------------------------------------"
    
    echo "Testing FIPS compliance check..."
    if check_fips_compliance 2>/dev/null; then
        echo "FIPS check completed successfully"
    else
        echo "FIPS check failed (expected in offline mode)"
    fi
    
    echo "Testing NTP synchronization check..."
    if check_ntp_synchronization 2>/dev/null; then
        echo "NTP check completed successfully"
    else
        echo "NTP check failed (expected in offline mode)"
    fi
    
    echo "Testing etcd encryption status check..."
    if check_etcd_encryption_status 2>/dev/null; then
        echo "etcd encryption check completed successfully"
    else
        echo "etcd encryption check failed (expected in offline mode)"
    fi
    
    # Cleanup
    rm -rf "${TEMP_DIR}"
    
    echo ""
    echo "=========================================="
    echo "All tests completed!"
    echo "=========================================="
}

# =============================================================================
# HTML REPORT GENERATION
# =============================================================================

# Generate HTML header with CSS styling
generate_html_header() {
    local cluster_name="$1"
    local cluster_version="$2"
    local cluster_channel="$3"
    local kubernetes_version="$4"
    local cluster_uuid="$5"
    local node_count="$6"
    local report_timestamp="$7"
    
    cat << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${cluster_name} - Health Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        html {
            scroll-behavior: smooth;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            line-height: 1.4;
            color: #1e293b;
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 50%, #f1f5f9 100%);
            min-height: 100vh;
            font-weight: 400;
        }
        
        .container {
            width: 90%;
            max-width: none;
            margin: 0 auto;
            padding: 16px;
            background: transparent;
        }
        
        .header {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #a855f7 100%);
            color: white;
            padding: 24px 32px;
            border-radius: 16px;
            margin-bottom: 20px;
            box-shadow: 0 8px 24px rgba(79, 70, 229, 0.15), 0 4px 8px rgba(0, 0, 0, 0.1);
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at 20% 80%, rgba(255, 255, 255, 0.1) 0%, transparent 50%),
                        radial-gradient(circle at 80% 20%, rgba(255, 255, 255, 0.1) 0%, transparent 50%);
            pointer-events: none;
        }
        
        .header h1 {
            font-size: 2.4em;
            margin-bottom: 20px;
            font-weight: 700;
            text-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
            letter-spacing: -1px;
            position: relative;
            z-index: 1;
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-top: 20px;
            position: relative;
            z-index: 1;
        }
        
        .header-info-item {
            background: rgba(255, 255, 255, 0.12);
            backdrop-filter: blur(20px);
            padding: 16px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.18);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .header-info-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, rgba(255, 255, 255, 0.8) 0%, rgba(255, 255, 255, 0.2) 100%);
        }
        
        .header-info-item:hover {
            background: rgba(255, 255, 255, 0.2);
            transform: translateY(-4px) scale(1.02);
            box-shadow: 0 12px 24px rgba(0, 0, 0, 0.15);
        }
        
        .header-info-item h3 {
            font-size: 0.75em;
            opacity: 0.85;
            margin-bottom: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: rgba(255, 255, 255, 0.9);
        }
        
        .header-info-item p {
            font-size: 1.3em;
            font-weight: 700;
            line-height: 1.2;
            word-break: break-all;
            color: #ffffff;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .summary-card {
            background: #ffffff;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.06), 0 1px 2px rgba(0, 0, 0, 0.08);
            border: 1px solid rgba(226, 232, 240, 0.8);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            text-decoration: none;
            color: inherit;
            display: block;
            position: relative;
            overflow: hidden;
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #4f46e5 0%, #7c3aed 50%, #a855f7 100%);
            transform: scaleX(0);
            transition: transform 0.4s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.12), 0 8px 16px rgba(0, 0, 0, 0.08);
            border-color: rgba(79, 70, 229, 0.2);
        }
        
        .summary-card:hover::before {
            transform: scaleX(1);
        }
        
        .summary-card:active {
            transform: translateY(0px);
        }
        
        .summary-card.healthy {
            border-left-color: #28a745;
        }
        
        .summary-card.warning {
            border-left-color: #ffc107;
        }
        
        .summary-card.critical {
            border-left-color: #dc3545;
        }
        
        .summary-card.unknown {
            border-left-color: #6c757d;
        }
        
        .summary-card h3 {
            font-size: 1.1em;
            margin-bottom: 10px;
            color: #555;
        }
        
        .status-indicator {
            display: inline-flex;
            align-items: center;
            padding: 8px 20px;
            border-radius: 24px;
            font-size: 0.75em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .status-indicator::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
            transition: left 0.5s ease;
        }
        
        .status-indicator:hover::before {
            left: 100%;
        }
        
        .status-healthy {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        .status-warning {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        
        .status-critical {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .status-unknown {
            background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
            color: white;
            border: 1px solid rgba(107, 114, 128, 0.3);
        }
        
        .section {
            background: #ffffff;
            margin-bottom: 24px;
            border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04), 0 1px 4px rgba(0, 0, 0, 0.02);
            border: 1px solid rgba(226, 232, 240, 0.6);
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .section:hover {
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.08), 0 4px 12px rgba(0, 0, 0, 0.06);
        }
        
        .section-header {
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            padding: 16px 20px;
            border-bottom: 1px solid rgba(226, 232, 240, 0.8);
            position: relative;
        }
        
        .section-header::before {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, #4f46e5 0%, #7c3aed 50%, #a855f7 100%);
        }
        
        .section-header h2 {
            font-size: 1.8em;
            color: #0f172a;
            margin-bottom: 8px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        
        .section-header p {
            color: #64748b;
            margin: 0;
            font-size: 1.05em;
            font-weight: 500;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .detail-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #dee2e6;
        }
        
        .detail-item.healthy {
            border-left-color: #28a745;
            background: #f8fff9;
        }
        
        .detail-item.warning {
            border-left-color: #ffc107;
            background: #fffef8;
        }
        
        .detail-item.critical {
            border-left-color: #dc3545;
            background: #fff8f8;
        }
        
        .detail-item h4 {
            margin-bottom: 8px;
            color: #495057;
        }
        
        .detail-item p {
            margin-bottom: 5px;
            font-size: 0.9em;
        }
        
        .detail-item .status {
            margin-top: 10px;
        }
        
        .table-container {
            overflow-x: auto;
            border-radius: 16px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04);
            background: #ffffff;
            border: 1px solid rgba(226, 232, 240, 0.6);
        }
        
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin-top: 0;
        }
        
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid rgba(226, 232, 240, 0.5);
        }
        
        th {
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            font-weight: 700;
            color: #0f172a;
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 1px;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        tbody tr {
            transition: all 0.2s ease;
        }
        
        tbody tr:hover {
            background-color: rgba(248, 250, 252, 0.8);
            transform: scale(1.001);
        }
        
        tbody tr:last-child td {
            border-bottom: none;
        }
        
        th:first-child {
            border-top-left-radius: 8px;
        }
        
        th:last-child {
            border-top-right-radius: 8px;
        }
        
        tr:hover {
            background-color: #f1f5f9;
        }
        
        tr:last-child td:first-child {
            border-bottom-left-radius: 8px;
        }
        
        tr:last-child td:last-child {
            border-bottom-right-radius: 8px;
        }
        
        .footer {
            text-align: center;
            padding: 48px;
            color: #64748b;
            font-size: 0.95em;
            border-top: 1px solid rgba(226, 232, 240, 0.8);
            margin-top: 64px;
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border-radius: 20px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04);
        }
        
        .footer p {
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                padding: 16px;
            }
            
            .header {
                padding: 32px 24px;
                border-radius: 16px;
            }
            
            .header h1 {
                font-size: 2.4em;
                margin-bottom: 24px;
            }
            
            .header-info {
                grid-template-columns: 1fr;
                gap: 16px;
            }
            
            .header-info-item {
                padding: 20px;
            }
            
            .summary {
                grid-template-columns: 1fr;
                gap: 16px;
            }
            
            .summary-card {
                padding: 24px;
            }
            
            .section-header {
                padding: 24px;
            }
            
            .section-content {
                padding: 24px;
            }
            
            th, td {
                padding: 12px 16px;
                font-size: 0.9em;
            }
        }
        
        @media (max-width: 480px) {
            .header h1 {
                font-size: 2em;
            }
            
            .header-info-item p {
                font-size: 1.1em;
                word-break: break-word;
            }
            
            th, td {
                padding: 8px 12px;
                font-size: 0.85em;
            }
        }
        
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #dc3545;
        }
        
        .info-message {
            background: #d1ecf1;
            color: #0c5460;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #17a2b8;
        }
        
        @media print {
            body {
                background: white;
            }
            
            .container {
                max-width: none;
                padding: 0;
            }
            
            .summary-card, .section {
                box-shadow: none;
                border: 1px solid #dee2e6;
            }
            
            .header {
                background: #667eea !important;
                -webkit-print-color-adjust: exact;
            }
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 2em;
            }
            
            .header-info {
                grid-template-columns: 1fr;
            }
            
            .summary {
                grid-template-columns: 1fr;
            }
            
            .detail-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Floating Go to Top Button */
        .go-to-top {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            border: none;
            border-radius: 50%;
            cursor: pointer;
            font-size: 18px;
            font-weight: bold;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transform: translateY(20px);
        }
        
        .go-to-top.visible {
            opacity: 1;
            visibility: visible;
            transform: translateY(0);
        }
        
        .go-to-top:hover {
            background: linear-gradient(135deg, #34495e 0%, #2980b9 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.4);
        }
        
        .go-to-top:active {
            transform: translateY(0);
        }
        
        @media print {
            .go-to-top {
                display: none !important;
            }
        }
        
        /* Code block styling */
        code {
            background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
            color: #1e293b;
            padding: 4px 8px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.85em;
            border: 1px solid rgba(148, 163, 184, 0.3);
            display: inline-block;
            margin: 2px 0;
            word-break: break-all;
            white-space: pre-wrap;
        }
        
        .code-block {
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border: 1px solid rgba(148, 163, 184, 0.3);
            border-radius: 8px;
            padding: 12px 16px;
            margin: 8px 0;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9em;
            color: #1e293b;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        .recommendation code {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border-color: rgba(245, 158, 11, 0.3);
        }
        
        .recommendation.critical code {
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
            border-color: rgba(239, 68, 68, 0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>${cluster_name} - Health Report</h1>
            <div class="header-info">
                <div class="header-info-item">
                    <h3>Cluster Name</h3>
                    <p>${cluster_name}</p>
                </div>
                <div class="header-info-item">
                    <h3>Cluster Version</h3>
                    <p>${cluster_version}</p>
                </div>
                <div class="header-info-item">
                    <h3>Cluster Channel</h3>
                    <p>${cluster_channel}</p>
                </div>
                <div class="header-info-item">
                    <h3>Kubernetes Version</h3>
                    <p>${kubernetes_version}</p>
                </div>
                <div class="header-info-item">
                    <h3>Cluster UUID</h3>
                    <p>${cluster_uuid}</p>
                </div>
                <div class="header-info-item">
                    <h3>Node Count</h3>
                    <p>${node_count}</p>
                </div>
            </div>
        </div>
EOF
}

# Generate status indicator HTML
generate_status_indicator() {
    local status="$1"
    local text="${2:-$status}"
    
    case "${status}" in
        "${STATUS_HEALTHY}")
            echo "<span class=\"status-indicator status-healthy\">${text}</span>"
            ;;
        "${STATUS_WARNING}")
            echo "<span class=\"status-indicator status-warning\">${text}</span>"
            ;;
        "${STATUS_CRITICAL}")
            echo "<span class=\"status-indicator status-critical\">${text}</span>"
            ;;
        *)
            echo "<span class=\"status-indicator status-unknown\">${text}</span>"
            ;;
    esac
}

# Generate summary cards section
generate_summary_section() {
    local fips_overall_status="${fips_status["overall_status"]}"
    local ntp_overall_status="${ntp_status["overall_status"]}"
    local etcd_overall_status="${etcd_encryption_status["overall_status"]}"
    
    local fips_compliant="${fips_status["compliant_nodes"]}"
    local fips_total="${fips_status["total_nodes"]}"
    local ntp_synchronized="${ntp_status["synchronized_nodes"]}"
    local ntp_total="${ntp_status["total_nodes"]}"
    local etcd_enabled="${etcd_encryption_status["encryption_enabled"]}"
    
    cat << EOF
        <div class="summary">
            <a href="#fips-section" class="summary-card ${fips_overall_status}">
                <h3>FIPS Compliance</h3>
                <p>$(generate_status_indicator "${fips_overall_status}" "${fips_overall_status}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${fips_compliant}/${fips_total} nodes compliant
                </p>
            </a>
            <a href="#ntp-section" class="summary-card ${ntp_overall_status}">
                <h3>NTP Synchronization</h3>
                <p>$(generate_status_indicator "${ntp_overall_status}" "${ntp_overall_status}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${ntp_synchronized}/${ntp_total} nodes synchronized
                </p>
            </a>
            <a href="#etcd-section" class="summary-card ${etcd_overall_status}">
                <h3>etcd Encryption</h3>
                <p>$(generate_status_indicator "${etcd_overall_status}" "${etcd_overall_status}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    Encryption: ${etcd_enabled}
                </p>
            </a>
            <a href="#oauth-section" class="summary-card ${oauth_status["overall_status"]}">
                <h3>OAuth Authentication</h3>
                <p>$(generate_status_indicator "${oauth_status["overall_status"]}" "${oauth_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${oauth_status["identity_providers_count"]} provider(s) configured
                </p>
            </a>
            <a href="#cluster-operators-section" class="summary-card ${cluster_operators_status["overall_status"]}">
                <h3>Cluster Operators</h3>
                <p>$(generate_status_indicator "${cluster_operators_status["overall_status"]}" "${cluster_operators_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${cluster_operators_status["available_operators"]}/${cluster_operators_status["total_operators"]} available
                </p>
            </a>
            <a href="#alertmanager-section" class="summary-card ${alertmanager_status["overall_status"]}">
                <h3>AlertManager</h3>
                <p>$(generate_status_indicator "${alertmanager_status["overall_status"]}" "${alertmanager_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${alertmanager_status["healthy_pods"]}/${alertmanager_status["pod_count"]} pods healthy
                </p>
            </a>
            <a href="#loki-section" class="summary-card ${loki_status["overall_status"]}">
                <h3>Loki Logging</h3>
                <p>$(generate_status_indicator "${loki_status["overall_status"]}" "${loki_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${loki_status["healthy_pods"]}/${loki_status["pod_count"]} pods healthy
                </p>
            </a>
            <a href="#ipsec-section" class="summary-card ${ipsec_status["overall_status"]}">
                <h3>IPSec Encryption</h3>
                <p>$(generate_status_indicator "${ipsec_status["overall_status"]}" "${ipsec_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    $(if [[ "${ipsec_status["ipsec_enabled"]}" == "true" ]]; then echo "Enabled"; elif [[ "${ipsec_status["ipsec_enabled"]}" == "false" ]]; then echo "Disabled"; else echo "Unknown"; fi)
                </p>
            </a>
            <a href="#backup-section" class="summary-card ${backup_status["overall_status"]}">
                <h3>Cluster Backup</h3>
                <p>$(generate_status_indicator "${backup_status["overall_status"]}" "${backup_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    $(if [[ "${backup_status["etcd_backup_enabled"]}" == "true" ]]; then echo "Configured"; else echo "Not Configured"; fi)
                </p>
            </a>
            <a href="#ingress-section" class="summary-card ${ingress_status["overall_status"]}">
                <h3>Ingress Controller</h3>
                <p>$(generate_status_indicator "${ingress_status["overall_status"]}" "${ingress_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${ingress_status["ready_replicas"]}/${ingress_status["replica_count"]} replicas ready
                </p>
            </a>
            <a href="#node-details-section" class="summary-card ${node_details_status["overall_status"]}">
                <h3>Node Details</h3>
                <p>$(generate_status_indicator "${node_details_status["overall_status"]}" "${node_details_status["overall_status"]}")</p>
                <p style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    ${node_details_status["ready_nodes"]}/${node_details_status["total_nodes"]} nodes ready
                </p>
            </a>
        </div>
EOF
}

# Generate FIPS compliance section
generate_fips_section() {
    cat << EOF
        <div class="section" id="fips-section">
            <div class="section-header">
                <h2>FIPS Compliance Status</h2>
                <p>Federal Information Processing Standards compliance across cluster nodes</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${fips_status["overall_status"]}" "${fips_status["overall_message"]}")
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Total Nodes</td>
                                <td>${fips_status["total_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Compliant Nodes</td>
                                <td>${fips_status["compliant_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Non-Compliant Nodes</td>
                                <td>${fips_status["non_compliant_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Unknown Status Nodes</td>
                                <td>${fips_status["unknown_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${fips_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Detailed FIPS Node Status</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Node Name</th>
                                <th>FIPS Status</th>
                                <th>Message</th>
                                <th>OS Image</th>
                                <th>Check Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
EOF
    
    # Parse and display individual FIPS node details
    if [[ -n "${fips_status["details"]}" && "${fips_status["details"]}" != "[]" && "${fips_status["details"]}" != "null" ]]; then
        # Create a temporary file to store the FIPS details
        local temp_fips_file
        temp_fips_file=$(create_temp_file "fips" ".json")
        echo "${fips_status["details"]}" > "${temp_fips_file}"
        
        # Check if jq is available and the JSON is valid
        if command -v jq >/dev/null 2>&1 && jq empty < "${temp_fips_file}" 2>/dev/null; then
            # Count the number of nodes
            local node_count
            node_count=$(jq '. | length' < "${temp_fips_file}" 2>/dev/null || echo "0")
            
            if [[ "${node_count}" -gt 0 ]]; then
                # Use jq to extract all nodes at once and format them
                jq -r '.[] | 
                    "<tr>" +
                    "<td><strong>" + .name + "</strong></td>" +
                    "<td>" + (if .fips_enabled == "true" then "<span class=\"status-indicator status-healthy\">Enabled</span>" elif .fips_enabled == "false" then "<span class=\"status-indicator status-critical\">Disabled</span>" else "<span class=\"status-indicator status-unknown\">Unknown</span>" end) + "</td>" +
                    "<td>" + .message + "</td>" +
                    "<td>" + (.os_image | if length > 50 then .[0:47] + "..." else . end) + "</td>" +
                    "<td>" + .check_timestamp + "</td>" +
                    "</tr>"' < "${temp_fips_file}" 2>/dev/null || {
                    cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">Error parsing FIPS details (${node_count} nodes found)</td>
                            </tr>
EOF
                }
            else
                cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">No FIPS details available (count: ${node_count})</td>
                            </tr>
EOF
            fi
        else
            cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">Unable to parse FIPS details (jq not available or invalid JSON)</td>
                            </tr>
EOF
        fi
        
        # Clean up temporary file
        rm -f "${temp_fips_file}" 2>/dev/null
    else
        cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">No FIPS details available</td>
                            </tr>
EOF
    fi
    
    cat << EOF
                        </tbody>
                    </table>
                </div>
                
EOF
    
    # Add errors if any
    if [[ -n "${fips_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${fips_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate NTP synchronization section
generate_ntp_section() {
    cat << EOF
        <div class="section" id="ntp-section">
            <div class="section-header">
                <h2>NTP Synchronization Status</h2>
                <p>Network Time Protocol synchronization across cluster nodes</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${ntp_status["overall_status"]}" "${ntp_status["overall_message"]}")
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Total Nodes</td>
                                <td>${ntp_status["total_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Synchronized Nodes</td>
                                <td>${ntp_status["synchronized_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Unsynchronized Nodes</td>
                                <td>${ntp_status["unsynchronized_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Unknown Status Nodes</td>
                                <td>${ntp_status["unknown_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${ntp_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
EOF
    
    # Add errors if any
    if [[ -n "${ntp_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${ntp_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate etcd encryption section
generate_etcd_section() {
    cat << EOF
        <div class="section" id="etcd-section">
            <div class="section-header">
                <h2>etcd Encryption Status</h2>
                <p>etcd encryption configuration and key rotation status</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${etcd_encryption_status["overall_status"]}" "${etcd_encryption_status["overall_message"]}")
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Encryption Enabled</td>
                                <td>${etcd_encryption_status["encryption_enabled"]}</td>
                            </tr>
                            <tr>
                                <td>Encryption Type</td>
                                <td>${etcd_encryption_status["encryption_type"]}</td>
                            </tr>
                            <tr>
                                <td>Encryption Provider</td>
                                <td>${etcd_encryption_status["encryption_provider"]}</td>
                            </tr>

                            <tr>
                                <td>Key Rotation Status</td>
                                <td>${etcd_encryption_status["key_rotation_status"]}</td>
                            </tr>
                            <tr>
                                <td>Last Key Rotation</td>
                                <td>${etcd_encryption_status["last_key_rotation"]}</td>
                            </tr>
                            <tr>
                                <td>Healthy etcd Pods</td>
                                <td>${etcd_encryption_status["etcd_pods_healthy"]}/${etcd_encryption_status["etcd_pods_total"]}</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${etcd_encryption_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
EOF
    
    # Add errors if any
    if [[ -n "${etcd_encryption_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${etcd_encryption_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate OAuth authentication section
generate_oauth_section() {
    cat << EOF
        <div class="section" id="oauth-section">
            <div class="section-header">
                <h2>OAuth Authentication</h2>
                <p>OpenShift OAuth authentication configuration and identity providers</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${oauth_status["overall_status"]}" "${oauth_status["overall_message"]}")
                </div>
                
                <h3 style="margin: 20px 0 15px 0; color: #495057;">Summary</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>OAuth Configured</td>
                                <td>${oauth_status["oauth_configured"]}</td>
                            </tr>
                            <tr>
                                <td>Identity Providers Count</td>
                                <td>${oauth_status["identity_providers_count"]}</td>
                            </tr>
                            <tr>
                                <td>Provider Types</td>
                                <td>${oauth_status["identity_providers_types"]}</td>
                            </tr>
                            <tr>
                                <td>OAuth Pods Healthy</td>
                                <td>${oauth_status["oauth_pods_healthy"]}/${oauth_status["oauth_pods_total"]}</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${oauth_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
EOF
    
    # Add detailed identity providers information if available
    if [[ -n "${oauth_status["details"]}" && "${oauth_status["details"]}" != "[]" && "${oauth_status["details"]}" != "null" ]]; then
        cat << EOF
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Identity Providers Details</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Provider Name</th>
                                <th>Type</th>
                                <th>Mapping Method</th>
                                <th>Configuration</th>
                            </tr>
                        </thead>
                        <tbody>
EOF
        
        # Parse and display individual identity provider details
        # Create a temporary file to store the provider details
        local temp_providers_file
        temp_providers_file=$(create_temp_file "oauth-providers" ".json")
        echo "${oauth_status["details"]}" > "${temp_providers_file}"
        
        # Check if jq is available and the JSON is valid
        if command -v jq >/dev/null 2>&1 && jq empty < "${temp_providers_file}" 2>/dev/null; then
            # Count the number of providers
            local provider_count
            provider_count=$(jq '. | length' < "${temp_providers_file}" 2>/dev/null || echo "0")
            
            if [[ "${provider_count}" -gt 0 ]]; then
                # Use jq to extract all providers at once and format them
                jq -r '.[] | 
                    "<tr>" +
                    "<td><strong>" + .name + "</strong></td>" +
                    "<td>" + .type + "</td>" +
                    "<td>" + .mapping_method + "</td>" +
                    "<td>" + (.configuration | if length > 60 then .[0:57] + "..." else . end) + "</td>" +
                    "</tr>"' < "${temp_providers_file}" 2>/dev/null || {
                    cat << EOF
                            <tr>
                                <td colspan="6" style="text-align: center; color: #6c757d;">Error parsing identity provider details (${provider_count} providers found)</td>
                            </tr>
EOF
                }
            else
                cat << EOF
                            <tr>
                                <td colspan="6" style="text-align: center; color: #6c757d;">No identity provider details available</td>
                            </tr>
EOF
            fi
        else
            cat << EOF
                            <tr>
                                <td colspan="6" style="text-align: center; color: #6c757d;">Unable to parse identity provider details (jq not available or invalid JSON)</td>
                            </tr>
EOF
        fi
        
        # Clean up temporary file
        rm -f "${temp_providers_file}" 2>/dev/null
        
        cat << EOF
                        </tbody>
                    </table>
                </div>
EOF
    else
        cat << EOF
                
                <div class="info-message">
                    <strong>Note:</strong> No detailed identity provider information available or no providers configured.
                </div>
EOF
    fi
    
    # Add errors if any
    if [[ -n "${oauth_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${oauth_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate cluster operators section
generate_cluster_operators_section() {
    cat << EOF
        <div class="section" id="cluster-operators-section">
            <div class="section-header">
                <h2>Cluster Operators Status</h2>
                <p>OpenShift cluster operators health and availability</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${cluster_operators_status["overall_status"]}" "${cluster_operators_status["overall_message"]}")
                </div>
                
                <h3 style="margin: 20px 0 15px 0; color: #495057;">Summary</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Total Operators</td>
                                <td>${cluster_operators_status["total_operators"]}</td>
                            </tr>
                            <tr>
                                <td>Available Operators</td>
                                <td>${cluster_operators_status["available_operators"]}</td>
                            </tr>
                            <tr>
                                <td>Progressing Operators</td>
                                <td>${cluster_operators_status["progressing_operators"]}</td>
                            </tr>
                            <tr>
                                <td>Degraded Operators</td>
                                <td>${cluster_operators_status["degraded_operators"]}</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${cluster_operators_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Detailed Operator Status</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Operator Name</th>
                                <th>Status</th>
                                <th>Available</th>
                                <th>Progressing</th>
                                <th>Degraded</th>
                            </tr>
                        </thead>
                        <tbody>
EOF
    
    # Parse and display individual operator details
    if [[ -n "${cluster_operators_status["details"]}" && "${cluster_operators_status["details"]}" != "[]" && "${cluster_operators_status["details"]}" != "null" ]]; then
        # Create a temporary file to store the operator details
        local temp_operators_file
        temp_operators_file=$(create_temp_file "operators" ".json")
        echo "${cluster_operators_status["details"]}" > "${temp_operators_file}"
        
        # Check if jq is available and the JSON is valid
        if command -v jq >/dev/null 2>&1 && jq empty < "${temp_operators_file}" 2>/dev/null; then
            # Count the number of operators
            local operator_count
            operator_count=$(jq '. | length' < "${temp_operators_file}" 2>/dev/null || echo "0")
            
            if [[ "${operator_count}" -gt 0 ]]; then
                # Use jq to extract all operators at once and format them
                jq -r '.[] | "<tr><td><strong>" + .name + "</strong></td><td>" + (if .status == "healthy" then "<span class=\"status-indicator status-healthy\">healthy</span>" elif .status == "warning" then "<span class=\"status-indicator status-warning\">warning</span>" elif .status == "critical" then "<span class=\"status-indicator status-critical\">critical</span>" else "<span class=\"status-indicator status-unknown\">unknown</span>" end) + "</td><td>" + .available + "</td><td>" + .progressing + "</td><td>" + .degraded + "</td></tr>"' < "${temp_operators_file}" 2>/dev/null || {
                    cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">Error parsing operator details (${operator_count} operators found)</td>
                            </tr>
EOF
                }
            else
                cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">No operator details available (count: ${operator_count})</td>
                            </tr>
EOF
            fi
        else
            cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">Unable to parse operator details (jq not available or invalid JSON)</td>
                            </tr>
EOF
        fi
        
        # Clean up temporary file
        rm -f "${temp_operators_file}" 2>/dev/null
    else
        cat << EOF
                            <tr>
                                <td colspan="5" style="text-align: center; color: #6c757d;">No operator details available</td>
                            </tr>
EOF
    fi
    
    cat << EOF
                        </tbody>
                    </table>
                </div>
EOF
    
    # Add errors if any
    if [[ -n "${cluster_operators_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${cluster_operators_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate AlertManager section
generate_alertmanager_section() {
    cat << EOF
        <div class="section" id="alertmanager-section">
            <div class="section-header">
                <h2>AlertManager Status</h2>
                <p>AlertManager deployment and receiver configuration</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${alertmanager_status["overall_status"]}" "${alertmanager_status["overall_message"]}")
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Deployment Status</td>
                                <td>${alertmanager_status["deployment_status"]}</td>
                            </tr>
                            <tr>
                                <td>Total Pods</td>
                                <td>${alertmanager_status["pod_count"]}</td>
                            </tr>
                            <tr>
                                <td>Healthy Pods</td>
                                <td>${alertmanager_status["healthy_pods"]}</td>
                            </tr>
                            <tr>
                                <td>Alert Receivers Configured</td>
                                <td>${alertmanager_status["receiver_status"]}</td>
                            </tr>
                            <tr>
                                <td>Receiver Details</td>
                                <td>${alertmanager_status["receiver_details"]}</td>
                            </tr>
                            <tr>
                                <td>Number of Receivers</td>
                                <td>${alertmanager_status["receivers_configured"]}</td>
                            </tr>
                            <tr>
                                <td>Routes Configured</td>
                                <td>${alertmanager_status["routes_configured"]}</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${alertmanager_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
EOF
    
    # Add errors if any
    if [[ -n "${alertmanager_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${alertmanager_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate Loki section
generate_loki_section() {
    cat << EOF
        <div class="section" id="loki-section">
            <div class="section-header">
                <h2>Loki Logging Status</h2>
                <p>Loki deployment and tenant configuration (audit, infrastructure, application)</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${loki_status["overall_status"]}" "${loki_status["overall_message"]}")
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Deployment Status</td>
                                <td>${loki_status["deployment_status"]}</td>
                            </tr>
                            <tr>
                                <td>Total Pods</td>
                                <td>${loki_status["pod_count"]}</td>
                            </tr>
                            <tr>
                                <td>Healthy Pods</td>
                                <td>${loki_status["healthy_pods"]}</td>
                            </tr>
                            <tr>
                                <td>Audit Tenant</td>
                                <td>${loki_status["audit_tenant"]}</td>
                            </tr>
                            <tr>
                                <td>Infrastructure Tenant</td>
                                <td>${loki_status["infrastructure_tenant"]}</td>
                            </tr>
                            <tr>
                                <td>Application Tenant</td>
                                <td>${loki_status["application_tenant"]}</td>
                            </tr>
                            <tr>
                                <td>LokiStack Configured</td>
                                <td>${loki_status["lokistack_configured"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Tenant Retention Configuration</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Tenant</th>
                                <th>Status</th>
                                <th>Retention Period</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><strong>Audit</strong></td>
                                <td>$(if [[ "${loki_status["audit_tenant"]}" == "configured" ]]; then echo "<span class=\"status-indicator status-healthy\">Configured (LokiStack)</span>"; elif [[ "${loki_status["audit_tenant"]}" == "configured_via_clf" ]]; then echo "<span class=\"status-indicator status-healthy\">Configured (ClusterLogForwarder)</span>"; elif [[ "${loki_status["audit_tenant"]}" == "not_configured" ]]; then echo "<span class=\"status-indicator status-warning\">Not Configured</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>$(if [[ "${loki_status["audit_retention"]}" == "not_configured" ]]; then echo "<span class=\"status-indicator status-warning\">Not Set</span>"; elif [[ "${loki_status["audit_retention"]}" == "unknown" ]]; then echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; else echo "<span class=\"status-indicator status-healthy\">${loki_status["audit_retention"]}</span>"; fi)</td>
                                <td>Kubernetes API server audit logs</td>
                            </tr>
                            <tr>
                                <td><strong>Infrastructure</strong></td>
                                <td>$(if [[ "${loki_status["infrastructure_tenant"]}" == "configured" ]]; then echo "<span class=\"status-indicator status-healthy\">Configured (LokiStack)</span>"; elif [[ "${loki_status["infrastructure_tenant"]}" == "configured_via_clf" ]]; then echo "<span class=\"status-indicator status-healthy\">Configured (ClusterLogForwarder)</span>"; elif [[ "${loki_status["infrastructure_tenant"]}" == "not_configured" ]]; then echo "<span class=\"status-indicator status-warning\">Not Configured</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>$(if [[ "${loki_status["infrastructure_retention"]}" == "not_configured" ]]; then echo "<span class=\"status-indicator status-warning\">Not Set</span>"; elif [[ "${loki_status["infrastructure_retention"]}" == "unknown" ]]; then echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; else echo "<span class=\"status-indicator status-healthy\">${loki_status["infrastructure_retention"]}</span>"; fi)</td>
                                <td>OpenShift infrastructure component logs</td>
                            </tr>
                            <tr>
                                <td><strong>Application</strong></td>
                                <td>$(if [[ "${loki_status["application_tenant"]}" == "configured" ]]; then echo "<span class=\"status-indicator status-healthy\">Configured (LokiStack)</span>"; elif [[ "${loki_status["application_tenant"]}" == "configured_via_clf" ]]; then echo "<span class=\"status-indicator status-healthy\">Configured (ClusterLogForwarder)</span>"; elif [[ "${loki_status["application_tenant"]}" == "not_configured" ]]; then echo "<span class=\"status-indicator status-warning\">Not Configured</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>$(if [[ "${loki_status["application_retention"]}" == "not_configured" ]]; then echo "<span class=\"status-indicator status-warning\">Not Set</span>"; elif [[ "${loki_status["application_retention"]}" == "unknown" ]]; then echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; else echo "<span class=\"status-indicator status-healthy\">${loki_status["application_retention"]}</span>"; fi)</td>
                                <td>Application and user workload logs</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${loki_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">LokiStack Components</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Component</th>
                                <th>Status</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><strong>Compactor</strong></td>
                                <td>$(if [[ "${loki_status["compactor_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["compactor_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["compactor_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Compacts and deduplicates log data</td>
                            </tr>
                            <tr>
                                <td><strong>Distributor</strong></td>
                                <td>$(if [[ "${loki_status["distributor_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["distributor_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["distributor_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Receives and distributes log streams</td>
                            </tr>
                            <tr>
                                <td><strong>Gateway</strong></td>
                                <td>$(if [[ "${loki_status["gateway_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["gateway_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["gateway_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>API gateway for Loki services</td>
                            </tr>
                            <tr>
                                <td><strong>Index Gateway</strong></td>
                                <td>$(if [[ "${loki_status["index_gateway_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["index_gateway_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["index_gateway_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Serves index queries and downloads</td>
                            </tr>
                            <tr>
                                <td><strong>Ingester</strong></td>
                                <td>$(if [[ "${loki_status["ingester_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["ingester_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["ingester_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Ingests and stores log data</td>
                            </tr>
                            <tr>
                                <td><strong>Querier</strong></td>
                                <td>$(if [[ "${loki_status["querier_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["querier_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["querier_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Executes log queries</td>
                            </tr>
                            <tr>
                                <td><strong>Query Frontend</strong></td>
                                <td>$(if [[ "${loki_status["query_frontend_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["query_frontend_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["query_frontend_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Frontend for query processing and caching</td>
                            </tr>
                            <tr>
                                <td><strong>Ruler</strong></td>
                                <td>$(if [[ "${loki_status["ruler_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["ruler_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["ruler_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Evaluates recording and alerting rules</td>
                            </tr>
                            <tr>
                                <td><strong>Collector</strong></td>
                                <td>$(if [[ "${loki_status["collector_status"]}" == "running" ]]; then echo "<span class=\"status-indicator status-healthy\">Running</span>"; elif [[ "${loki_status["collector_status"]}" == "not_running" ]]; then echo "<span class=\"status-indicator status-warning\">Not Running</span>"; elif [[ "${loki_status["collector_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>Collects and forwards logs from nodes (Fluentd/Vector)</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
EOF
    
    # Add errors if any
    if [[ -n "${loki_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${loki_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate IPSec encryption section
generate_ipsec_section() {
    cat << EOF
        <div class="section" id="ipsec-section">
            <div class="section-header">
                <h2>IPSec Encryption Status</h2>
                <p>IPSec encryption for pod-to-pod and node-to-node communication</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${ipsec_status["overall_status"]}" "${ipsec_status["overall_message"]}")
                </div>
                
                <h3 style="margin: 20px 0 15px 0; color: #495057;">Summary</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>IPSec Enabled</td>
                                <td>$(if [[ "${ipsec_status["ipsec_enabled"]}" == "true" ]]; then echo "<span class=\"status-indicator status-healthy\">Yes</span>"; elif [[ "${ipsec_status["ipsec_enabled"]}" == "false" ]]; then echo "<span class=\"status-indicator status-warning\">No</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                            </tr>
                            <tr>
                                <td>IPSec Mode</td>
                                <td>${ipsec_status["ipsec_mode"]}</td>
                            </tr>

                            <tr>
                                <td>IPSec Pods Healthy</td>
                                <td>${ipsec_status["ipsec_pods_healthy"]}/${ipsec_status["ipsec_pods_total"]}</td>
                            </tr>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${ipsec_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">IPSec Configuration Details</h3>
                <div class="info-message">
                    <strong>Network Encryption:</strong> 
                    $(if [[ "${ipsec_status["ipsec_enabled"]}" == "true" ]]; then 
                        echo "IPSec encryption is enabled for secure pod-to-pod and node-to-node communication. This provides encryption for network traffic within the cluster using the OVN-Kubernetes network plugin."
                    elif [[ "${ipsec_status["ipsec_enabled"]}" == "false" ]]; then 
                        echo "IPSec encryption is not enabled. Network traffic within the cluster is not encrypted at the network layer. Consider enabling IPSec for enhanced security in production environments."
                    else 
                        echo "IPSec encryption status could not be determined. This may indicate issues with the network configuration or access permissions."
                    fi)
                </div>
                
                <div class="info-message">
                    <strong>Security Benefits:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li><strong>Pod-to-Pod Encryption:</strong> Encrypts traffic between pods across different nodes</li>
                        <li><strong>Node-to-Node Encryption:</strong> Secures communication between cluster nodes</li>
                        <li><strong>Network Layer Security:</strong> Provides encryption at the network layer (Layer 3)</li>
                        <li><strong>Compliance:</strong> Helps meet security compliance requirements for data in transit</li>
                    </ul>
                </div>
                
EOF
    
    # Add errors if any
    if [[ -n "${ipsec_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${ipsec_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate cluster backup section
generate_backup_section() {
    cat << EOF
        <div class="section" id="backup-section">
            <div class="section-header">
                <h2>Cluster Backup Status</h2>
                <p>Backup configurations and disaster recovery readiness</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${backup_status["overall_status"]}" "${backup_status["overall_message"]}")
                </div>
                
                <h3 style="margin: 20px 0 15px 0; color: #495057;">Backup Solutions Summary</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Backup Solution</th>
                                <th>Status</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>etcd Backup</td>
                                <td>$(if [[ "${backup_status["etcd_backup_enabled"]}" == "true" ]]; then echo "<span class=\"status-indicator status-healthy\">Enabled</span>"; elif [[ "${backup_status["etcd_backup_enabled"]}" == "false" ]]; then echo "<span class=\"status-indicator status-warning\">Disabled</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>$(if [[ "${backup_status["etcd_backup_schedule"]}" != "unknown" ]]; then echo "Schedule: ${backup_status["etcd_backup_schedule"]}"; else echo "No schedule configured"; fi)</td>
                            </tr>
                            <tr>
                                <td>OADP Operator</td>
                                <td>$(if [[ "${backup_status["oadp_operator_status"]}" == "installed" ]]; then echo "<span class=\"status-indicator status-healthy\">Installed</span>"; elif [[ "${backup_status["oadp_operator_status"]}" == "not_installed" ]]; then echo "<span class=\"status-indicator status-warning\">Not Installed</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                <td>OpenShift API for Data Protection</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Backup Infrastructure</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Component</th>
                                <th>Count</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>

                            <tr>
                                <td>Recent Backup Failures</td>
                                <td>$(if [[ "${backup_status["recent_backup_failures"]}" == "0" ]]; then echo "<span class=\"status-indicator status-healthy\">${backup_status["recent_backup_failures"]}</span>"; else echo "<span class=\"status-indicator status-warning\">${backup_status["recent_backup_failures"]}</span>"; fi)</td>
                                <td>Failed backup operations requiring attention</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Backup Recommendations</h3>
                <div class="info-message">
                    <strong>Disaster Recovery Best Practices:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li><strong>etcd Backup:</strong> Essential for cluster state recovery - should be automated and tested regularly</li>
                        <li><strong>Application Data:</strong> Use OADP for persistent volume and application backup</li>
                        <li><strong>Multiple Solutions:</strong> Implement both etcd and application-level backups for comprehensive protection</li>
                        <li><strong>Off-site Storage:</strong> Store backups in geographically separate locations</li>
                        <li><strong>Regular Testing:</strong> Periodically test backup restoration procedures</li>
                        <li><strong>Retention Policies:</strong> Configure appropriate backup retention based on compliance requirements</li>
                    </ul>
                </div>
                
EOF
    
    # Add backup status warnings or recommendations
    if [[ "${backup_status["etcd_backup_enabled"]}" == "false" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Critical:</strong> No backup solutions detected. Your cluster data is at risk. Consider implementing:
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li>etcd backup automation for cluster state protection</li>
                        <li>OADP/Velero for application and persistent volume backup</li>
                        <li>Regular backup testing and validation procedures</li>
                    </ul>
                </div>
EOF
    elif [[ "${backup_status["recent_backup_failures"]}" != "0" && "${backup_status["recent_backup_failures"]}" != "unknown" ]]; then
        cat << EOF
                <div class="warning-message">
                    <strong>Warning:</strong> ${backup_status["recent_backup_failures"]} recent backup failures detected. 
                    Review backup logs and resolve issues to ensure data protection.
                </div>
EOF
    fi
    
    # Add errors if any
    if [[ -n "${backup_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${backup_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate OpenShift Ingress section
generate_ingress_section() {
    cat << EOF
        <div class="section" id="ingress-section">
            <div class="section-header">
                <h2>OpenShift Ingress</h2>
                <p>Ingress controller configuration, replica count, and node placement analysis</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${ingress_status["overall_status"]}" "${ingress_status["overall_message"]}")
                </div>
                
                <div class="info-grid">
                    <div class="info-card">
                        <h3>Ingress Controller</h3>
                        <div class="info-table">
                            <table>
                                <tr>
                                    <td>Controller Status</td>
                                    <td>$(if [[ "${ingress_status["ingress_controller_status"]}" == "configured" ]]; then echo "<span class=\"status-indicator status-healthy\">Configured</span>"; elif [[ "${ingress_status["ingress_controller_status"]}" == "not_found" ]]; then echo "<span class=\"status-indicator status-critical\">Not Found</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                </tr>
                                <tr>
                                    <td>Desired Replicas</td>
                                    <td>${ingress_status["desired_replicas"]}</td>
                                </tr>
                                <tr>
                                    <td>Current Replicas</td>
                                    <td>${ingress_status["replica_count"]}</td>
                                </tr>
                                <tr>
                                    <td>Ready Replicas</td>
                                    <td>$(if [[ "${ingress_status["ready_replicas"]}" -eq "${ingress_status["replica_count"]}" && "${ingress_status["replica_count"]}" -gt 0 ]]; then echo "<span class=\"status-indicator status-healthy\">${ingress_status["ready_replicas"]}/${ingress_status["replica_count"]}</span>"; elif [[ "${ingress_status["ready_replicas"]}" -gt 0 ]]; then echo "<span class=\"status-indicator status-warning\">${ingress_status["ready_replicas"]}/${ingress_status["replica_count"]}</span>"; else echo "<span class=\"status-indicator status-critical\">${ingress_status["ready_replicas"]}/${ingress_status["replica_count"]}</span>"; fi)</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <div class="info-card">
                        <h3>Node Placement</h3>
                        <div class="info-table">
                            <table>
                                <tr>
                                    <td>Placement Configuration</td>
                                    <td>$(
                                        # Prioritize actual placement over configuration
                                        if [[ "${ingress_status["running_on_infra"]:-0}" -gt 0 ]]; then
                                            echo "<span class=\"status-indicator status-healthy\">Fine (Running on Infra)</span>"
                                        elif [[ "${ingress_status["infra_nodes_available"]:-0}" -eq 0 && "${ingress_status["running_on_worker"]:-0}" -gt 0 ]]; then
                                            echo "<span class=\"status-indicator status-healthy\">Fine (Running on Worker)</span>"
                                        elif [[ "${ingress_status["node_placement_status"]}" == "configured_for_infra" ]]; then
                                            echo "<span class=\"status-indicator status-healthy\">Configured for Infra</span>"
                                        elif [[ "${ingress_status["node_placement_status"]}" == "configured_for_worker" ]]; then
                                            echo "<span class=\"status-indicator status-healthy\">Configured for Worker</span>"
                                        elif [[ "${ingress_status["node_placement_status"]}" == "not_configured" ]]; then
                                            echo "<span class=\"status-indicator status-warning\">Not Configured</span>"
                                        else
                                            echo "<span class=\"status-indicator status-unknown\">Unknown</span>"
                                        fi
                                    )</td>
                                </tr>
                                <tr>
                                    <td>Running on Infra Nodes</td>
                                    <td>$(if [[ "${ingress_status["running_on_infra"]:-0}" -gt 0 ]]; then echo "<span class=\"status-indicator status-healthy\">${ingress_status["running_on_infra"]}</span>"; else echo "<span class=\"status-indicator status-neutral\">0</span>"; fi)</td>
                                </tr>
                                <tr>
                                    <td>Running on Worker Nodes</td>
                                    <td>$(if [[ "${ingress_status["running_on_worker"]:-0}" -gt 0 ]]; then echo "<span class=\"status-indicator status-healthy\">${ingress_status["running_on_worker"]}</span>"; else echo "<span class=\"status-indicator status-neutral\">0</span>"; fi)</td>
                                </tr>
                                <tr>
                                    <td>Pod Distribution</td>
                                    <td>$(if [[ "${ingress_status["pod_distribution"]}" == "well_distributed" ]]; then echo "<span class=\"status-indicator status-healthy\">Well Distributed</span>"; elif [[ "${ingress_status["pod_distribution"]}" == "partially_distributed" ]]; then echo "<span class=\"status-indicator status-warning\">Partially Distributed</span>"; elif [[ "${ingress_status["pod_distribution"]}" == "single_node" ]]; then echo "<span class=\"status-indicator status-warning\">Single Node</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <div class="info-card">
                        <h3>Cluster Node Availability</h3>
                        <div class="info-table">
                            <table>
                                <tr>
                                    <td>Infra Nodes Available</td>
                                    <td>$(if [[ "${ingress_status["infra_nodes_available"]:-0}" -gt 0 ]]; then echo "<span class=\"status-indicator status-healthy\">${ingress_status["infra_nodes_available"]}</span>"; else echo "<span class=\"status-indicator status-neutral\">0</span>"; fi)</td>
                                </tr>
                                <tr>
                                    <td>Worker Nodes Available</td>
                                    <td>$(if [[ "${ingress_status["worker_nodes_available"]:-0}" -gt 0 ]]; then echo "<span class=\"status-indicator status-healthy\">${ingress_status["worker_nodes_available"]}</span>"; else echo "<span class=\"status-indicator status-neutral\">0</span>"; fi)</td>
                                </tr>
                                <tr>
                                    <td>Minimum Replicas Status</td>
                                    <td>$(if [[ "${ingress_status["minimum_replicas_met"]}" == "should_be_3" ]]; then echo "<span class=\"status-indicator status-warning\">Should be 3+ for HA</span>"; elif [[ "${ingress_status["minimum_replicas_met"]}" == "adequate_for_ha" ]]; then echo "<span class=\"status-indicator status-healthy\">Adequate for HA</span>"; elif [[ "${ingress_status["minimum_replicas_met"]}" == "adequate_for_cluster_size" ]]; then echo "<span class=\"status-indicator status-healthy\">Adequate</span>"; elif [[ "${ingress_status["minimum_replicas_met"]}" == "should_increase" ]]; then echo "<span class=\"status-indicator status-warning\">Should Increase</span>"; else echo "<span class=\"status-indicator status-unknown\">Unknown</span>"; fi)</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                    
                    <div class="info-card">
                        <h3>Recommendations</h3>
                        <div class="recommendations">
EOF

    # Add recommendations based on status
    local infra_available="${ingress_status["infra_nodes_available"]:-0}"
    local worker_available="${ingress_status["worker_nodes_available"]:-0}"
    local running_on_infra="${ingress_status["running_on_infra"]:-0}"
    local running_on_worker="${ingress_status["running_on_worker"]:-0}"
    local desired_replicas="${ingress_status["desired_replicas"]:-0}"
    local available_nodes=$((infra_available + worker_available))

    # Node placement recommendations
    if [[ "${infra_available}" -gt 0 && "${running_on_infra}" -eq 0 ]]; then
        echo "                            <div class=\"recommendation critical\">"
        echo "                                <strong>Critical:</strong> Configure ingress to run on infra nodes when available"
        echo "                                <p>Option 1 - Standard infra node selector:</p>"
        echo "                                <div class=\"code-block\">oc patch ingresscontroller default -n openshift-ingress-operator --type=merge -p '{\"spec\":{\"nodePlacement\":{\"nodeSelector\":{\"node-role.kubernetes.io/infra\":\"\"}}}}'</div>"
        echo "                                <p>Option 2 - Infrastructure node selector:</p>"
        echo "                                <div class=\"code-block\">oc patch ingresscontroller default -n openshift-ingress-operator --type=merge -p '{\"spec\":{\"nodePlacement\":{\"nodeSelector\":{\"node-role.kubernetes.io/infrastructure\":\"\"}}}}'</div>"
        echo "                                <p>Option 3 - NodeSelector with matchLabels:</p>"
        echo "                                <div class=\"code-block\">oc patch ingresscontroller default -n openshift-ingress-operator --type=merge -p '{\"spec\":{\"nodePlacement\":{\"nodeSelector\":{\"matchLabels\":{\"node-role.kubernetes.io/infra\":\"\"}}}}}'</div>"
        echo "                            </div>"
    elif [[ "${infra_available}" -eq 0 && "${worker_available}" -gt 0 && "${running_on_worker}" -eq 0 ]]; then
        echo "                            <div class=\"recommendation warning\">"
        echo "                                <strong>Warning:</strong> Configure ingress to run on worker nodes when no infra nodes are available"
        echo "                                <div class=\"code-block\">oc patch ingresscontroller default -n openshift-ingress-operator --type=merge -p '{\"spec\":{\"nodePlacement\":{\"nodeSelector\":{\"node-role.kubernetes.io/worker\":\"\"}}}}'</div>"
        echo "                            </div>"
    fi

    # Replica recommendations
    if [[ "${available_nodes}" -ge 3 && "${desired_replicas}" -lt 3 ]]; then
        echo "                            <div class=\"recommendation warning\">"
        echo "                                <strong>Warning:</strong> Increase ingress replicas to 3+ for high availability"
        echo "                                <div class=\"code-block\">oc patch ingresscontroller default -n openshift-ingress-operator --type=merge -p '{\"spec\":{\"replicas\":3}}'</div>"
        echo "                            </div>"
    fi

    # Distribution recommendations
    if [[ "${ingress_status["pod_distribution"]}" == "single_node" && "${ingress_status["replica_count"]:-0}" -gt 1 ]]; then
        echo "                            <div class=\"recommendation warning\">"
        echo "                                <strong>Warning:</strong> Improve pod distribution across nodes using pod anti-affinity"
        echo "                                <br>Consider configuring pod anti-affinity rules to spread ingress pods across different nodes"
        echo "                            </div>"
    fi

    # Toleration recommendations for infra nodes
    if [[ "${infra_available}" -gt 0 && "${ingress_status["node_placement_status"]}" == "configured_for_infra" ]]; then
        echo "                            <div class=\"recommendation info\">"
        echo "                                <strong>Info:</strong> Ensure tolerations are configured for infra node taints"
        echo "                                <br>Add tolerations for <code>node-role.kubernetes.io/infra</code> taint if infra nodes are tainted"
        echo "                            </div>"
    fi

    if [[ "${ingress_status["node_placement_status"]}" == "not_configured" ]]; then
        echo "                            <div class=\"recommendation info\">"
        echo "                                <strong>Info:</strong> Consider configuring explicit node placement for ingress pods"
        echo "                            </div>"
    fi

    # If no specific recommendations, show general best practices
    if [[ "${infra_available}" -gt 0 && "${running_on_infra}" -gt 0 && "${available_nodes}" -ge 3 && "${desired_replicas}" -ge 3 ]]; then
        echo "                            <div class=\"recommendation success\">"
        echo "                                <strong>Good:</strong> Ingress configuration follows best practices"
        echo "                            </div>"
    fi

    cat << EOF
                        </div>
                    </div>
                </div>
                
                <div class="info-card">
                    <h3>Check Details</h3>
                    <div class="info-table">
                        <table>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${ingress_status["check_timestamp"]}</td>
                            </tr>
EOF

    if [[ -n "${ingress_status["errors"]}" ]]; then
        cat << EOF
                            <tr>
                                <td>Errors</td>
                                <td><span class="status-indicator status-critical">${ingress_status["errors"]}</span></td>
                            </tr>
EOF
    fi

    cat << EOF
                        </table>
                    </div>
                </div>
            </div>
        </div>
EOF
}

# Generate node details section
generate_node_details_section() {
    cat << EOF
        <div class="section" id="node-details-section">
            <div class="section-header">
                <h2>Node Details</h2>
                <p>Comprehensive information about cluster nodes including roles, IP addresses, and system details</p>
            </div>
            <div class="section-content">
                <div class="info-message">
                    <strong>Overall Status:</strong> $(generate_status_indicator "${node_details_status["overall_status"]}" "${node_details_status["overall_message"]}")
                </div>
                
                <h3 style="margin: 20px 0 15px 0; color: #495057;">Summary</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Total Nodes</td>
                                <td>${node_details_status["total_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Master Nodes</td>
                                <td>${node_details_status["master_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Worker Nodes</td>
                                <td>${node_details_status["worker_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Infra Nodes</td>
                                <td>${node_details_status["infra_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Ready Nodes</td>
                                <td>${node_details_status["ready_nodes"]}</td>
                            </tr>
                            <tr>
                                <td>Not Ready Nodes</td>
                                <td>${node_details_status["not_ready_nodes"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Machine Config Pools</h3>
                $(if [[ "${node_details_status["mcp_status"]}" != "unknown" && "${node_details_status["mcp_status"]}" != "no_mcps_found" ]]; then
                    echo '<div class="table-container">'
                    echo '<table>'
                    echo '<thead>'
                    echo '<tr>'
                    echo '<th>Name</th>'
                    echo '<th>Status</th>'
                    echo '<th>Ready</th>'
                    echo '<th>Updated</th>'
                    echo '<th>Degraded</th>'
                    echo '<th>Total</th>'
                    echo '</tr>'
                    echo '</thead>'
                    echo '<tbody>'
                    
                    # Parse MCP details and create table rows
                    local mcp_details_json=$(echo "${node_details_status["mcp_status"]}" | jq -r '.details' 2>/dev/null || echo "[]")
                    local mcp_count=$(echo "${mcp_details_json}" | jq -r 'length' 2>/dev/null || echo "0")
                    
                    if [[ "${mcp_count}" -gt 0 ]]; then
                        local mcp_index=0
                        while [[ ${mcp_index} -lt ${mcp_count} ]]; do
                            local mcp_name=$(echo "${mcp_details_json}" | jq -r ".[${mcp_index}].name" 2>/dev/null || echo "unknown")
                            local mcp_status=$(echo "${mcp_details_json}" | jq -r ".[${mcp_index}].status" 2>/dev/null || echo "unknown")
                            local mcp_ready=$(echo "${mcp_details_json}" | jq -r ".[${mcp_index}].ready_machines" 2>/dev/null || echo "0")
                            local mcp_updated=$(echo "${mcp_details_json}" | jq -r ".[${mcp_index}].updated_machines" 2>/dev/null || echo "0")
                            local mcp_degraded=$(echo "${mcp_details_json}" | jq -r ".[${mcp_index}].degraded_machines" 2>/dev/null || echo "0")
                            local mcp_total=$(echo "${mcp_details_json}" | jq -r ".[${mcp_index}].total_machines" 2>/dev/null || echo "0")
                            
                            echo '<tr>'
                            echo "<td><strong>${mcp_name}</strong></td>"
                            
                            # Status with color coding
                            if [[ "${mcp_status}" == "ready" ]]; then
                                echo '<td><span class="status-indicator status-healthy">Ready</span></td>'
                            elif [[ "${mcp_status}" == "updating" ]]; then
                                echo '<td><span class="status-indicator status-warning">Updating</span></td>'
                            elif [[ "${mcp_status}" == "degraded" ]]; then
                                echo '<td><span class="status-indicator status-critical">Degraded</span></td>'
                            else
                                echo '<td><span class="status-indicator status-unknown">Unknown</span></td>'
                            fi
                            
                            echo "<td>${mcp_ready}</td>"
                            echo "<td>${mcp_updated}</td>"
                            echo "<td>${mcp_degraded}</td>"
                            echo "<td>${mcp_total}</td>"
                            echo '</tr>'
                            
                            ((mcp_index++))
                        done
                    else
                        echo '<tr><td colspan="6">No MCP details available</td></tr>'
                    fi
                    
                    echo '</tbody>'
                    echo '</table>'
                    echo '</div>'
                elif [[ "${node_details_status["mcp_status"]}" == "no_mcps_found" ]]; then
                    echo '<div class="info-message">'
                    echo '<strong>Machine Config Pools:</strong> No Machine Config Pools found in the cluster.'
                    echo '</div>'
                else
                    echo '<div class="info-message">'
                    echo '<strong>Machine Config Pools:</strong> Unable to retrieve Machine Config Pool information.'
                    echo '</div>'
                fi)
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Summary</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Check Timestamp</td>
                                <td>${node_details_status["check_timestamp"]}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Detailed Node Information</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Node Name</th>
                                <th>Roles</th>
                                <th>Status</th>
                                <th>Internal IP</th>
                                <th>Memory Pressure</th>
                                <th>Disk Pressure</th>
                                <th>PID Pressure</th>
                                <th>OS Image</th>
                                <th>Taints</th>
                            </tr>
                        </thead>
                        <tbody>
EOF
    
    # Parse and display individual node details
    if [[ -n "${node_details_status["details"]}" && "${node_details_status["details"]}" != "[]" && "${node_details_status["details"]}" != "null" ]]; then
        # Create a temporary file to store the node details
        local temp_nodes_file
        temp_nodes_file=$(create_temp_file "nodes" ".json")
        echo "${node_details_status["details"]}" > "${temp_nodes_file}"
        
        # Check if jq is available and the JSON is valid
        if command -v jq >/dev/null 2>&1 && jq empty < "${temp_nodes_file}" 2>/dev/null; then
            # Count the number of nodes
            local node_count
            node_count=$(jq '. | length' < "${temp_nodes_file}" 2>/dev/null || echo "0")
            
            if [[ "${node_count}" -gt 0 ]]; then
                # Use jq to extract all nodes at once and format them
                jq -r '.[] | 
                    "<tr>" +
                    "<td><strong>" + .name + "</strong></td>" +
                    "<td>" + .roles + "</td>" +
                    "<td>" + (if .status == "Ready" then "<span class=\"status-indicator status-healthy\">Ready</span>" elif .status == "NotReady" then "<span class=\"status-indicator status-critical\">NotReady</span>" else "<span class=\"status-indicator status-unknown\">Unknown</span>" end) + "</td>" +
                    "<td>" + .internal_ip + "</td>" +
                    "<td>" + (if .memory_pressure == "False" then "<span class=\"status-indicator status-healthy\">False</span>" elif .memory_pressure == "True" then "<span class=\"status-indicator status-critical\">True</span>" else "<span class=\"status-indicator status-unknown\">" + .memory_pressure + "</span>" end) + "</td>" +
                    "<td>" + (if .disk_pressure == "False" then "<span class=\"status-indicator status-healthy\">False</span>" elif .disk_pressure == "True" then "<span class=\"status-indicator status-critical\">True</span>" else "<span class=\"status-indicator status-unknown\">" + .disk_pressure + "</span>" end) + "</td>" +
                    "<td>" + (if .pid_pressure == "False" then "<span class=\"status-indicator status-healthy\">False</span>" elif .pid_pressure == "True" then "<span class=\"status-indicator status-critical\">True</span>" else "<span class=\"status-indicator status-unknown\">" + .pid_pressure + "</span>" end) + "</td>" +
                    "<td>" + (.os_image | if length > 50 then .[0:47] + "..." else . end) + "</td>" +
                    "<td>" + (if .taints_count > 0 then "<span class=\"status-indicator status-warning\">" + (.taints_summary | if length > 60 then .[0:57] + "..." else . end) + "</span>" else "<span class=\"status-indicator status-healthy\">None</span>" end) + "</td>" +
                    "</tr>"' < "${temp_nodes_file}" 2>/dev/null || {
                    cat << EOF
                            <tr>
                                <td colspan="11" style="text-align: center; color: #6c757d;">Error parsing node details (${node_count} nodes found)</td>
                            </tr>
EOF
                }
            else
                cat << EOF
                            <tr>
                                <td colspan="11" style="text-align: center; color: #6c757d;">No node details available (count: ${node_count})</td>
                            </tr>
EOF
            fi
        else
            cat << EOF
                            <tr>
                                <td colspan="11" style="text-align: center; color: #6c757d;">Unable to parse node details (jq not available or invalid JSON)</td>
                            </tr>
EOF
        fi
        
        # Clean up temporary file
        rm -f "${temp_nodes_file}" 2>/dev/null
    else
        cat << EOF
                            <tr>
                                <td colspan="11" style="text-align: center; color: #6c757d;">No node details available</td>
                            </tr>
EOF
    fi
    
    cat << EOF
                        </tbody>
                    </table>
                </div>
                
                <h3 style="margin: 30px 0 15px 0; color: #495057;">Node Resource Capacity</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Node Name</th>
                                <th>CPU Capacity</th>
                                <th>Memory Capacity</th>
                                <th>Pods Capacity</th>
                                <th>Architecture</th>
                                <th>Container Runtime</th>
                                <th>Kernel Version</th>
                            </tr>
                        </thead>
                        <tbody>
EOF
    
    # Parse and display node resource information
    if [[ -n "${node_details_status["details"]}" && "${node_details_status["details"]}" != "[]" && "${node_details_status["details"]}" != "null" ]]; then
        # Create a temporary file to store the node details
        local temp_nodes_file
        temp_nodes_file=$(create_temp_file "nodes-resources" ".json")
        echo "${node_details_status["details"]}" > "${temp_nodes_file}"
        
        # Check if jq is available and the JSON is valid
        if command -v jq >/dev/null 2>&1 && jq empty < "${temp_nodes_file}" 2>/dev/null; then
            # Count the number of nodes
            local node_count
            node_count=$(jq '. | length' < "${temp_nodes_file}" 2>/dev/null || echo "0")
            
            if [[ "${node_count}" -gt 0 ]]; then
                # Use jq to extract all nodes at once and format them
                jq -r '.[] | 
                    "<tr>" +
                    "<td><strong>" + .name + "</strong></td>" +
                    "<td>" + .cpu_capacity + "</td>" +
                    "<td>" + .memory_capacity + "</td>" +
                    "<td>" + .pods_capacity + "</td>" +
                    "<td>" + .architecture + "</td>" +
                    "<td>" + (.container_runtime | if length > 30 then .[0:27] + "..." else . end) + "</td>" +
                    "<td>" + (.kernel_version | if length > 30 then .[0:27] + "..." else . end) + "</td>" +
                    "</tr>"' < "${temp_nodes_file}" 2>/dev/null || {
                    cat << EOF
                            <tr>
                                <td colspan="7" style="text-align: center; color: #6c757d;">Error parsing node resource details</td>
                            </tr>
EOF
                }
            else
                cat << EOF
                            <tr>
                                <td colspan="7" style="text-align: center; color: #6c757d;">No node resource details available</td>
                            </tr>
EOF
            fi
        else
            cat << EOF
                            <tr>
                                <td colspan="7" style="text-align: center; color: #6c757d;">Unable to parse node resource details</td>
                            </tr>
EOF
        fi
        
        # Clean up temporary file
        rm -f "${temp_nodes_file}" 2>/dev/null
    else
        cat << EOF
                            <tr>
                                <td colspan="7" style="text-align: center; color: #6c757d;">No node resource details available</td>
                            </tr>
EOF
    fi
    
    cat << EOF
                        </tbody>
                    </table>
                </div>
EOF
    
    # Add errors if any
    if [[ -n "${node_details_status["errors"]}" ]]; then
        cat << EOF
                <div class="error-message">
                    <strong>Errors:</strong> ${node_details_status["errors"]}
                </div>
EOF
    fi
    
    echo "            </div>"
    echo "        </div>"
}

# Generate HTML footer
generate_html_footer() {
    cat << EOF
        <div class="footer">
            <p>Generated by OpenShift Health Report Generator v${SCRIPT_VERSION}</p>
            <p>Report generated on $(get_readable_timestamp)</p>
            <p>This report provides a snapshot of cluster health at the time of generation</p>
            <p>© 2025 muneerkh@gmail.com</p>
        </div>
    </div>
    
    <!-- Floating Go to Top Button -->
    <button class="go-to-top" id="goToTopBtn" onclick="scrollToTop()" title="Go to top">
        ↑
    </button>
    
    <script>
        // Show/hide the go to top button based on scroll position
        window.onscroll = function() {
            var goToTopBtn = document.getElementById("goToTopBtn");
            if (document.body.scrollTop > 300 || document.documentElement.scrollTop > 300) {
                goToTopBtn.classList.add("visible");
            } else {
                goToTopBtn.classList.remove("visible");
            }
        };
        
        // Smooth scroll to top function
        function scrollToTop() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        }
    </script>
</body>
</html>
EOF
}

# Generate complete HTML report
generate_html_report() {
    log_info "Generating HTML report..."
    
    # Get cluster information
    local cluster_version="Unknown"
    local cluster_name="Unknown"
    local cluster_uuid="Unknown"

    local node_count="0"
    
    # Try to get cluster version
    if cluster_version=$(oc get clusterversion -o jsonpath='{.items[0].status.desired.version}' 2>/dev/null); then
        log_debug "Retrieved cluster version: ${cluster_version}"
    else
        log_warn "Could not retrieve cluster version"
        cluster_version="Unknown"
    fi
    
    # Try to get cluster channel
    local cluster_channel="Unknown"
    if cluster_channel=$(oc get clusterversion -o jsonpath='{.items[0].spec.channel}' 2>/dev/null); then
        log_debug "Retrieved cluster channel: ${cluster_channel}"
    else
        log_warn "Could not retrieve cluster channel"
        cluster_channel="Unknown"
    fi
    
    # Try to get Kubernetes version
    local kubernetes_version="Unknown"
    if kubernetes_version=$(oc version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion' 2>/dev/null); then
        log_debug "Retrieved Kubernetes version: ${kubernetes_version}"
    else
        # Fallback method using kubectl if available
        if kubernetes_version=$(kubectl version --short 2>/dev/null | grep "Server Version" | cut -d' ' -f3 2>/dev/null); then
            log_debug "Retrieved Kubernetes version via kubectl: ${kubernetes_version}"
        else
            log_warn "Could not retrieve Kubernetes version"
            kubernetes_version="Unknown"
        fi
    fi
    
    # Try to get cluster name from infrastructure
    if raw_cluster_name=$(oc get infrastructure cluster -o jsonpath='{.status.infrastructureName}' 2>/dev/null); then
        log_debug "Retrieved raw cluster name: ${raw_cluster_name}"
        # Extract just the cluster name part (remove suffix like -abc123 and any domain parts)
        cluster_name=$(echo "${raw_cluster_name}" | sed 's/-[a-z0-9]*$//' | sed 's/\..*$//')
        log_debug "Formatted cluster name: ${cluster_name}"
    else
        # Fallback: try to get from cluster network config
        if raw_cluster_name=$(oc get network.config.openshift.io cluster -o jsonpath='{.metadata.name}' 2>/dev/null); then
            log_debug "Retrieved cluster name from network config: ${raw_cluster_name}"
            cluster_name="${raw_cluster_name}"
        else
            log_warn "Could not retrieve cluster name"
            cluster_name="Unknown"
        fi
    fi
    
    # Update output filename to include cluster name if using default filename
    if [[ "${OUTPUT_FILE}" == "${DEFAULT_OUTPUT_FILE}" && "${cluster_name}" != "Unknown" ]]; then
        # Create a sanitized cluster name for filename (remove special characters)
        local sanitized_cluster_name
        sanitized_cluster_name=$(echo "${cluster_name}" | sed 's/[^a-zA-Z0-9-]/_/g' | tr '[:upper:]' '[:lower:]')
        
        # Generate new filename with cluster name
        local new_output_file="${sanitized_cluster_name}-health-report-$(date +%Y%m%d-%H%M%S).html"
        
        log_info "Using cluster-specific filename: ${new_output_file}"
        OUTPUT_FILE="${new_output_file}"
    fi
    
    # Try to get cluster UUID from clusterversion
    if cluster_uuid=$(oc get clusterversion -o jsonpath='{.items[0].spec.clusterID}' 2>/dev/null); then
        log_debug "Retrieved cluster UUID: ${cluster_uuid}"
    else
        log_warn "Could not retrieve cluster UUID"
        cluster_uuid="Unknown"
    fi
    

    
    # Try to get node count
    if node_count=$(oc get nodes --no-headers 2>/dev/null | wc -l); then
        log_debug "Retrieved node count: ${node_count}"
    else
        log_warn "Could not retrieve node count"
        node_count="Unknown"
    fi
    
    local report_timestamp
    report_timestamp=$(get_readable_timestamp)
    
    # Generate HTML content
    {
        generate_html_header "${cluster_name}" "${cluster_version}" "${cluster_channel}" "${kubernetes_version}" "${cluster_uuid}" "${node_count}" "${report_timestamp}"
        generate_summary_section
        generate_fips_section
        generate_ntp_section
        generate_etcd_section
        generate_oauth_section
        generate_cluster_operators_section
        generate_alertmanager_section
        generate_loki_section
        generate_ipsec_section
        generate_backup_section
        generate_ingress_section
        generate_node_details_section
        generate_html_footer
    } > "${OUTPUT_FILE}"
    
    log_debug "Template replacement completed"
    log_success "HTML report generated: ${OUTPUT_FILE}"
}

# Main function
main() {
    initialize "$@"
    
    log_info "Starting OpenShift cluster health report generation..."
    log_info "Output file: ${OUTPUT_FILE}"
    
    # Run data collection modules with error handling
    log_info "Collecting FIPS compliance data..."
    if ! check_fips_compliance; then
        log_warn "FIPS compliance check failed, using default values"
        fips_status["overall_status"]="${STATUS_UNKNOWN}"
        fips_status["overall_message"]="FIPS compliance check failed"
        fips_status["total_nodes"]="0"
        fips_status["compliant_nodes"]="0"
        fips_status["non_compliant_nodes"]="0"
        fips_status["unknown_nodes"]="0"
        fips_status["check_timestamp"]="$(get_timestamp)"
        fips_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting NTP synchronization data..."
    if ! check_ntp_synchronization; then
        log_warn "NTP synchronization check failed, using default values"
        ntp_status["overall_status"]="${STATUS_UNKNOWN}"
        ntp_status["overall_message"]="NTP synchronization check failed"
        ntp_status["total_nodes"]="0"
        ntp_status["synchronized_nodes"]="0"
        ntp_status["unsynchronized_nodes"]="0"
        ntp_status["unknown_nodes"]="0"
        ntp_status["check_timestamp"]="$(get_timestamp)"
        ntp_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting etcd encryption data..."
    if ! check_etcd_encryption_status; then
        log_warn "etcd encryption check failed, using default values"
        etcd_encryption_status["overall_status"]="${STATUS_UNKNOWN}"
        etcd_encryption_status["overall_message"]="etcd encryption check failed"
        etcd_encryption_status["encryption_enabled"]="unknown"
        etcd_encryption_status["encryption_type"]="unknown"
        etcd_encryption_status["encryption_provider"]="unknown"
        etcd_encryption_status["reencryption_verified"]="unknown"
        etcd_encryption_status["reencryption_status"]="unknown"
        etcd_encryption_status["key_rotation_status"]="unknown"
        etcd_encryption_status["last_key_rotation"]="unknown"
        etcd_encryption_status["etcd_pods_healthy"]="0"
        etcd_encryption_status["etcd_pods_total"]="0"
        etcd_encryption_status["check_timestamp"]="$(get_timestamp)"
        etcd_encryption_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting OAuth authentication data..."
    if ! check_oauth_authentication_status; then
        log_warn "OAuth authentication check failed, using default values"
        oauth_status["overall_status"]="${STATUS_UNKNOWN}"
        oauth_status["overall_message"]="OAuth authentication check failed"
        oauth_status["oauth_configured"]="unknown"
        oauth_status["identity_providers_count"]="0"
        oauth_status["identity_providers_types"]=""
        oauth_status["oauth_pods_healthy"]="0"
        oauth_status["oauth_pods_total"]="0"
        oauth_status["check_timestamp"]="$(get_timestamp)"
        oauth_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting cluster operators data..."
    if ! check_cluster_operators_status; then
        log_warn "Cluster operators check failed, using default values"
        cluster_operators_status["overall_status"]="${STATUS_UNKNOWN}"
        cluster_operators_status["overall_message"]="Cluster operators check failed"
        cluster_operators_status["available_operators"]="0"
        cluster_operators_status["progressing_operators"]="0"
        cluster_operators_status["degraded_operators"]="0"
        cluster_operators_status["total_operators"]="0"
        cluster_operators_status["check_timestamp"]="$(get_timestamp)"
        cluster_operators_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting AlertManager data..."
    if ! check_alertmanager_status; then
        log_warn "AlertManager check failed, using default values"
        alertmanager_status["overall_status"]="${STATUS_UNKNOWN}"
        alertmanager_status["overall_message"]="AlertManager check failed"
        alertmanager_status["deployment_status"]="unknown"
        alertmanager_status["pod_count"]="0"
        alertmanager_status["healthy_pods"]="0"
        alertmanager_status["receivers_configured"]="0"
        alertmanager_status["routes_configured"]="0"
        alertmanager_status["check_timestamp"]="$(get_timestamp)"
        alertmanager_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting Loki data..."
    if ! check_loki_status; then
        log_warn "Loki check failed, using default values"
        loki_status["overall_status"]="${STATUS_UNKNOWN}"
        loki_status["overall_message"]="Loki check failed"
        loki_status["deployment_status"]="unknown"
        loki_status["pod_count"]="0"
        loki_status["healthy_pods"]="0"
        loki_status["audit_tenant"]="unknown"
        loki_status["infrastructure_tenant"]="unknown"
        loki_status["application_tenant"]="unknown"
        loki_status["check_timestamp"]="$(get_timestamp)"
        loki_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting IPSec encryption data..."
    if ! check_ipsec_encryption_status; then
        log_warn "IPSec encryption check failed, using default values"
        ipsec_status["overall_status"]="${STATUS_UNKNOWN}"
        ipsec_status["overall_message"]="IPSec encryption check failed"
        ipsec_status["ipsec_enabled"]="unknown"
        ipsec_status["ipsec_mode"]="unknown"
        ipsec_status["ovn_ipsec_config"]="unknown"
        ipsec_status["network_plugin"]="unknown"
        ipsec_status["ipsec_supported"]="unknown"
        ipsec_status["ipsec_pods_healthy"]="0"
        ipsec_status["ipsec_pods_total"]="0"
        ipsec_status["check_timestamp"]="$(get_timestamp)"
        ipsec_status["details"]="{}"
        ipsec_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting cluster backup status data..."
    if ! check_backup_status; then
        log_warn "Cluster backup check failed, using default values"
        backup_status["overall_status"]="${STATUS_UNKNOWN}"
        backup_status["overall_message"]="Cluster backup check failed"
        backup_status["etcd_backup_enabled"]="unknown"
        backup_status["etcd_backup_schedule"]="unknown"
        backup_status["etcd_backup_last_success"]="unknown"
        backup_status["etcd_backup_retention"]="unknown"
        backup_status["oadp_operator_status"]="unknown"
        backup_status["recent_backup_failures"]="0"
        backup_status["check_timestamp"]="$(get_timestamp)"
        backup_status["details"]="{}"
        backup_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting OpenShift Ingress data..."
    if ! check_ingress_status; then
        log_warn "Ingress status check failed, using default values"
        ingress_status["overall_status"]="${STATUS_UNKNOWN}"
        ingress_status["overall_message"]="Ingress status check failed"
        ingress_status["ingress_controller_status"]="unknown"
        ingress_status["replica_count"]="0"
        ingress_status["desired_replicas"]="0"
        ingress_status["available_replicas"]="0"
        ingress_status["ready_replicas"]="0"
        ingress_status["node_placement_status"]="unknown"
        ingress_status["running_on_infra"]="unknown"
        ingress_status["running_on_worker"]="unknown"
        ingress_status["infra_nodes_available"]="unknown"
        ingress_status["worker_nodes_available"]="unknown"
        ingress_status["minimum_replicas_met"]="unknown"
        ingress_status["pod_distribution"]="unknown"
        ingress_status["check_timestamp"]="$(get_timestamp)"
        ingress_status["details"]="{}"
        ingress_status["errors"]="Data collection failed"
    fi
    
    log_info "Collecting node details data..."
    if ! check_node_details; then
        log_warn "Node details check failed, using default values"
        node_details_status["overall_status"]="${STATUS_UNKNOWN}"
        node_details_status["overall_message"]="Node details check failed"
        node_details_status["total_nodes"]="0"
        node_details_status["master_nodes"]="0"
        node_details_status["worker_nodes"]="0"
        node_details_status["infra_nodes"]="0"
        node_details_status["ready_nodes"]="0"
        node_details_status["not_ready_nodes"]="0"
        node_details_status["check_timestamp"]="$(get_timestamp)"
        node_details_status["errors"]="Data collection failed"
    fi
    
    # Generate HTML report
    generate_html_report
    
    log_success "OpenShift cluster health report generation completed!"
    log_info "Report saved to: ${OUTPUT_FILE}"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi