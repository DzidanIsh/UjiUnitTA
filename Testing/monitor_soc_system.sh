#!/bin/bash

# SOC System Real-time Monitoring Script
# Memonitor status sistem SOC secara real-time
# --------------------------------------------------------------------

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Konfigurasi monitoring
MONITOR_INTERVAL=30  # detik
LOG_FILE="/var/log/soc-incident-response/monitor.log"

# Fungsi untuk menampilkan status
show_status() {
    local component="$1"
    local status="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $status in
        "OK")
            echo -e "[$timestamp] ${GREEN}✅ $component: $message${NC}"
            ;;
        "WARNING")
            echo -e "[$timestamp] ${YELLOW}⚠️  $component: $message${NC}"
            ;;
        "ERROR")
            echo -e "[$timestamp] ${RED}❌ $component: $message${NC}"
            ;;
    esac
    
    # Log ke file
    echo "[$timestamp] $component: $message" >> "$LOG_FILE"
}

# Fungsi untuk cek status sistem
check_system_status() {
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE}      SOC SYSTEM STATUS - $(date)                           ${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    echo ""
    
    # 1. Cek Python processes
    PYTHON_PROCESSES=$(pgrep -f "soc_incident_response" | wc -l)
    if [ "$PYTHON_PROCESSES" -gt 0 ]; then
        show_status "Python Processes" "OK" "$PYTHON_PROCESSES SOC processes running"
    else
        show_status "Python Processes" "WARNING" "No SOC processes running"
    fi
    
    # 2. Cek Wazuh status
    if systemctl is-active --quiet wazuh-manager; then
        show_status "Wazuh Manager" "OK" "Service aktif"
    else
        show_status "Wazuh Manager" "ERROR" "Service tidak aktif"
    fi
    
    # 3. Cek disk space
    DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -lt 80 ]; then
        show_status "Disk Space" "OK" "Usage: ${DISK_USAGE}%"
    else
        show_status "Disk Space" "WARNING" "Usage: ${DISK_USAGE}% (high)"
    fi
    
    # 4. Cek memory usage
    MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
    if [ "$MEMORY_USAGE" -lt 80 ]; then
        show_status "Memory Usage" "OK" "Usage: ${MEMORY_USAGE}%"
    else
        show_status "Memory Usage" "WARNING" "Usage: ${MEMORY_USAGE}% (high)"
    fi
    
    # 5. Cek log files
    if [ -f "$LOG_FILE" ]; then
        LOG_SIZE=$(du -h "$LOG_FILE" | cut -f1)
        show_status "Log Files" "OK" "Size: $LOG_SIZE"
    else
        show_status "Log Files" "WARNING" "Log file tidak ditemukan"
    fi
    
    # 6. Cek network connectivity
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        show_status "Network" "OK" "Internet connectivity OK"
    else
        show_status "Network" "WARNING" "Internet connectivity issues"
    fi
    
    echo ""
}

# Main monitoring loop
main() {
    echo "Starting SOC System Monitoring..."
    echo "Monitoring interval: ${MONITOR_INTERVAL} seconds"
    echo "Log file: $LOG_FILE"
    echo "Press Ctrl+C to stop monitoring"
    echo ""
    
    # Buat direktori log jika tidak ada
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Loop monitoring
    while true; do
        check_system_status
        sleep "$MONITOR_INTERVAL"
        clear
    done
}

# Trap untuk cleanup
trap 'echo -e "\n${GREEN}Monitoring stopped.${NC}"; exit 0' INT

# Jalankan monitoring
main
