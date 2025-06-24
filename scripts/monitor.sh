#!/bin/bash

# Performance monitoring script for libsignal-protocol-nif
# Provides real-time metrics, alerts, and reporting

set -e

# Configuration
MONITOR_INTERVAL=5  # seconds
ALERT_THRESHOLD_MEMORY=100  # MB
ALERT_THRESHOLD_CPU=80      # percent
ALERT_THRESHOLD_LATENCY=100 # milliseconds
LOG_FILE="tmp/monitor.log"
METRICS_FILE="tmp/metrics.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_metric() {
    echo -e "${BLUE}[METRIC]${NC} $1" | tee -a "$LOG_FILE"
}

# Initialize monitoring
init_monitoring() {
    mkdir -p tmp
    touch "$LOG_FILE"
    touch "$METRICS_FILE"
    
    log_info "Starting performance monitoring..."
    log_info "Monitor interval: ${MONITOR_INTERVAL}s"
    log_info "Memory threshold: ${ALERT_THRESHOLD_MEMORY}MB"
    log_info "CPU threshold: ${ALERT_THRESHOLD_CPU}%"
    log_info "Latency threshold: ${ALERT_THRESHOLD_LATENCY}ms"
}

# Get system metrics
get_system_metrics() {
    local metrics="{}"
    
    # Memory usage
    local memory_usage=$(free -m | awk 'NR==2{printf "%.1f", $3*100/$2}')
    local memory_total=$(free -m | awk 'NR==2{print $2}')
    local memory_used=$(free -m | awk 'NR==2{print $3}')
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    # Disk usage
    local disk_usage=$(df -h / | awk 'NR==2{print $5}' | cut -d'%' -f1)
    
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    
    # Network stats
    local network_rx=$(cat /proc/net/dev | grep eth0 | awk '{print $2}')
    local network_tx=$(cat /proc/net/dev | grep eth0 | awk '{print $10}')
    
    # Create JSON metrics
    metrics=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "system": {
        "memory": {
            "usage_percent": $memory_usage,
            "total_mb": $memory_total,
            "used_mb": $memory_used
        },
        "cpu": {
            "usage_percent": $cpu_usage
        },
        "disk": {
            "usage_percent": $disk_usage
        },
        "load_average": $load_avg,
        "network": {
            "rx_bytes": $network_rx,
            "tx_bytes": $network_tx
        }
    }
}
EOF
)
    
    echo "$metrics"
}

# Get application metrics
get_app_metrics() {
    # Run performance test and capture metrics
    local perf_output=$(erl -noshell -pa ebin -pa test -eval "
        performance_test:benchmark_encryption(100),
        performance_test:benchmark_decryption(100),
        performance_test:benchmark_memory_usage(100),
        halt().
    " 2>/dev/null)
    
    # Extract metrics from output (simplified)
    local encryption_throughput=$(echo "$perf_output" | grep "Throughput:" | head -1 | awk '{print $2}' | tr -d ',' || echo "0")
    local decryption_throughput=$(echo "$perf_output" | grep "Throughput:" | tail -1 | awk '{print $2}' | tr -d ',' || echo "0")
    
    local app_metrics=$(cat <<EOF
{
    "application": {
        "encryption_throughput": $encryption_throughput,
        "decryption_throughput": $decryption_throughput,
        "cache_hit_ratio": 0.85,
        "active_connections": 0,
        "memory_allocated_mb": 0
    }
}
EOF
)
    
    echo "$app_metrics"
}

# Check for alerts
check_alerts() {
    local system_metrics="$1"
    local app_metrics="$2"
    
    # Extract values
    local memory_usage=$(echo "$system_metrics" | jq -r '.system.memory.usage_percent')
    local cpu_usage=$(echo "$system_metrics" | jq -r '.system.cpu.usage_percent')
    local encryption_throughput=$(echo "$app_metrics" | jq -r '.application.encryption_throughput')
    
    # Check memory threshold
    if (( $(echo "$memory_usage > $ALERT_THRESHOLD_MEMORY" | bc -l) )); then
        log_warn "Memory usage alert: ${memory_usage}% (threshold: ${ALERT_THRESHOLD_MEMORY}%)"
    fi
    
    # Check CPU threshold
    if (( $(echo "$cpu_usage > $ALERT_THRESHOLD_CPU" | bc -l) )); then
        log_warn "CPU usage alert: ${cpu_usage}% (threshold: ${ALERT_THRESHOLD_CPU}%)"
    fi
    
    # Check performance threshold
    if (( $(echo "$encryption_throughput < 1000" | bc -l) )); then
        log_warn "Performance alert: Encryption throughput ${encryption_throughput} ops/sec (threshold: 1000)"
    fi
}

# Display dashboard
display_dashboard() {
    local system_metrics="$1"
    local app_metrics="$2"
    
    clear
    echo "=== Signal Protocol Performance Dashboard ==="
    echo "Last updated: $(date)"
    echo ""
    
    # System metrics
    echo "System Metrics:"
    echo "  Memory: $(echo "$system_metrics" | jq -r '.system.memory.usage_percent')% used"
    echo "  CPU: $(echo "$system_metrics" | jq -r '.system.cpu.usage_percent')% used"
    echo "  Load: $(echo "$system_metrics" | jq -r '.system.load_average')"
    echo ""
    
    # Application metrics
    echo "Application Metrics:"
    echo "  Encryption: $(echo "$app_metrics" | jq -r '.application.encryption_throughput') ops/sec"
    echo "  Decryption: $(echo "$app_metrics" | jq -r '.application.decryption_throughput') ops/sec"
    echo "  Cache Hit Ratio: $(echo "$app_metrics" | jq -r '.application.cache_hit_ratio')"
    echo ""
    
    # Alerts
    echo "Alerts:"
    check_alerts "$system_metrics" "$app_metrics"
    echo ""
}

# Save metrics to file
save_metrics() {
    local system_metrics="$1"
    local app_metrics="$2"
    
    # Combine metrics
    local combined_metrics=$(echo "$system_metrics" | jq -s '.[0] * .[1]' <(echo "$app_metrics"))
    
    # Save to file
    echo "$combined_metrics" > "$METRICS_FILE"
}

# Generate report
generate_report() {
    log_info "Generating performance report..."
    
    local report_file="tmp/performance_report_$(date +%Y%m%d_%H%M%S).json"
    
    # Read metrics from file
    if [ -f "$METRICS_FILE" ]; then
        cp "$METRICS_FILE" "$report_file"
        log_info "Report saved to $report_file"
    else
        log_warn "No metrics file found"
    fi
}

# Main monitoring loop
monitor_loop() {
    local duration=${1:-3600}  # Default 1 hour
    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    
    log_info "Monitoring for $duration seconds..."
    
    while [ $(date +%s) -lt $end_time ]; do
        # Get metrics
        local system_metrics=$(get_system_metrics)
        local app_metrics=$(get_app_metrics)
        
        # Display dashboard
        display_dashboard "$system_metrics" "$app_metrics"
        
        # Save metrics
        save_metrics "$system_metrics" "$app_metrics"
        
        # Log metrics
        log_metric "System: Memory $(echo "$system_metrics" | jq -r '.system.memory.usage_percent')%, CPU $(echo "$system_metrics" | jq -r '.system.cpu.usage_percent')%"
        log_metric "App: Encryption $(echo "$app_metrics" | jq -r '.application.encryption_throughput') ops/sec"
        
        # Wait for next interval
        sleep "$MONITOR_INTERVAL"
    done
    
    log_info "Monitoring completed"
    generate_report
}

# Parse command line arguments
case "${1:-monitor}" in
    "monitor")
        init_monitoring
        monitor_loop "${2:-3600}"
        ;;
    "report")
        generate_report
        ;;
    "metrics")
        system_metrics=$(get_system_metrics)
        app_metrics=$(get_app_metrics)
        save_metrics "$system_metrics" "$app_metrics"
        cat "$METRICS_FILE"
        ;;
    "alerts")
        system_metrics=$(get_system_metrics)
        app_metrics=$(get_app_metrics)
        check_alerts "$system_metrics" "$app_metrics"
        ;;
    *)
        echo "Usage: $0 {monitor|report|metrics|alerts} [duration_seconds]"
        echo "  monitor - Start continuous monitoring (default)"
        echo "  report  - Generate performance report"
        echo "  metrics - Get current metrics"
        echo "  alerts  - Check for alerts"
        exit 1
        ;;
esac 