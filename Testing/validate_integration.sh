#!/bin/bash

# Script validasi integrasi sistem SOC Incident Response
# --------------------------------------------------------------------

source /etc/soc-config/config.conf

echo "================================================================="
echo "      VALIDASI INTEGRASI SOC INCIDENT RESPONSE                   "
echo "================================================================="
echo ""

# Fungsi untuk menampilkan status
show_status() {
    local component="$1"
    local status="$2"
    local message="$3"
    
    if [ "$status" = "OK" ]; then
        echo -e "✅ $component: $message"
    elif [ "$status" = "WARNING" ]; then
        echo -e "⚠️  $component: $message"
    else
        echo -e "❌ $component: $message"
    fi
}

# 1. Validasi Konfigurasi
echo "1. Validasi Konfigurasi..."
if [ -f "$CONFIG_FILE" ]; then
    show_status "Config File" "OK" "File konfigurasi ditemukan"
else
    show_status "Config File" "ERROR" "File konfigurasi tidak ditemukan"
    exit 1
fi

# 2. Validasi Script Python
echo "2. Validasi Script Python..."
for script in "$SOC_MAIN_SCRIPT" "$DETECTION_SCRIPT" "$CONTAINMENT_SCRIPT" "$ERADICATION_SCRIPT" "$RESTORE_SCRIPT" "$POSTIA_SCRIPT"; do
    script_path="$PYTHON_SCRIPTS_DIR/$script"
    if [ -f "$script_path" ]; then
        if python3 "$script_path" --help >/dev/null 2>&1; then
            show_status "$script" "OK" "Script dapat dijalankan"
        else
            show_status "$script" "WARNING" "Script ada tapi tidak dapat dijalankan"
        fi
    else
        show_status "$script" "ERROR" "Script tidak ditemukan"
    fi
done

# 3. Validasi Dependencies
echo "3. Validasi Dependencies..."
if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import requests, psutil, yaml" 2>/dev/null; then
        show_status "Python Dependencies" "OK" "Semua modul tersedia"
    else
        show_status "Python Dependencies" "WARNING" "Beberapa modul tidak tersedia"
    fi
else
    show_status "Python Dependencies" "ERROR" "Python3 tidak tersedia"
fi

# 4. Validasi Integrasi Wazuh
echo "4. Validasi Integrasi Wazuh..."
if [ -d "/var/ossec" ]; then
    if [ -f "/var/ossec/etc/ossec.conf" ]; then
        if grep -q "soc_incident_response" "/var/ossec/etc/ossec.conf"; then
            show_status "Wazuh Integration" "OK" "Script terintegrasi dengan Wazuh"
        else
            show_status "Wazuh Integration" "WARNING" "Script belum terintegrasi dengan Wazuh"
        fi
    else
        show_status "Wazuh Integration" "ERROR" "Konfigurasi Wazuh tidak ditemukan"
    fi
else
    show_status "Wazuh Integration" "WARNING" "Wazuh tidak terinstall"
fi

# 5. Validasi Direktori
echo "5. Validasi Direktori..."
for dir in "$WEB_DIR" "$BACKUP_DIR" "$QUARANTINE_DIR" "$LOG_DIR"; do
    if [ -d "$dir" ]; then
        show_status "Directory $dir" "OK" "Direktori tersedia"
    else
        show_status "Directory $dir" "WARNING" "Direktori tidak tersedia"
    fi
done

echo ""
echo "================================================================="
echo "      VALIDASI SELESAI                                           "
echo "================================================================="
