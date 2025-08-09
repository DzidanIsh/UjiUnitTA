#!/bin/bash

# SOC Incident Response Integration Validation Script
# Memvalidasi integrasi lengkap sistem SOC IRLC
# --------------------------------------------------------------------

# Colors untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}=================================================================${NC}"
echo -e "${BLUE}      VALIDASI INTEGRASI SOC INCIDENT RESPONSE                   ${NC}"
echo -e "${BLUE}=================================================================${NC}"
echo ""

# Fungsi untuk menampilkan status
show_status() {
    local component="$1"
    local status="$2"
    local message="$3"
    
    case $status in
        "OK")
            echo -e "${GREEN}✅ $component: $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $component: $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $component: $message${NC}"
            ;;
    esac
}

# Fungsi untuk menjalankan test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_exit="$3"
    
    echo -e "${BLUE}Running: $test_name${NC}"
    if eval "$command" >/dev/null 2>&1; then
        if [ $? -eq "$expected_exit" ]; then
            show_status "$test_name" "OK" "Test berhasil"
            return 0
        else
            show_status "$test_name" "WARNING" "Test berhasil tapi exit code tidak sesuai"
            return 1
        fi
    else
        show_status "$test_name" "ERROR" "Test gagal"
        return 1
    fi
}

# Counter untuk hasil test
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNING=0

# 1. VALIDASI KONFIGURASI
echo -e "${BLUE}1. VALIDASI KONFIGURASI${NC}"
echo "----------------------------------------"

# Cek file konfigurasi
if [ -f "/etc/soc-config/config.conf" ]; then
    show_status "Config File" "OK" "File konfigurasi ditemukan"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    show_status "Config File" "ERROR" "File konfigurasi tidak ditemukan"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Cek permission config
if [ -r "/etc/soc-config/config.conf" ]; then
    show_status "Config Permission" "OK" "File dapat dibaca"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    show_status "Config Permission" "ERROR" "File tidak dapat dibaca"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""

# 2. VALIDASI PYTHON ENVIRONMENT
echo -e "${BLUE}2. VALIDASI PYTHON ENVIRONMENT${NC}"
echo "----------------------------------------"

# Cek Python version
if command -v python3 >/dev/null 2>&1; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    show_status "Python3" "OK" "Version $PYTHON_VERSION tersedia"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    show_status "Python3" "ERROR" "Python3 tidak tersedia"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Cek pip
if command -v pip3 >/dev/null 2>&1; then
    show_status "Pip3" "OK" "Pip3 tersedia"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    show_status "Pip3" "WARNING" "Pip3 tidak tersedia"
    TESTS_WARNING=$((TESTS_WARNING + 1))
fi

echo ""

# 3. VALIDASI DEPENDENCIES
echo -e "${BLUE}3. VALIDASI DEPENDENCIES${NC}"
echo "----------------------------------------"

# Test import dependencies
if python3 -c "import requests, psutil, yaml" 2>/dev/null; then
    show_status "Core Dependencies" "OK" "requests, psutil, yaml tersedia"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    show_status "Core Dependencies" "WARNING" "Beberapa modul tidak tersedia"
    TESTS_WARNING=$((TESTS_WARNING + 1))
fi

# Test security dependencies
if python3 -c "import clamd, yara" 2>/dev/null; then
    show_status "Security Dependencies" "OK" "clamd, yara tersedia"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    show_status "Security Dependencies" "WARNING" "clamd atau yara tidak tersedia"
    TESTS_WARNING=$((TESTS_WARNING + 1))
fi

echo ""

# 4. VALIDASI SCRIPT PYTHON
echo -e "${BLUE}4. VALIDASI SCRIPT PYTHON${NC}"
echo "----------------------------------------"

# Daftar script yang harus ada
SCRIPTS=(
    "soc_incident_response.py"
    "Deteksi.py"
    "containment.py"
    "eradication.py"
    "restore.py"
    "PostIA.py"
)

for script in "${SCRIPTS[@]}"; do
    if [ -f "$script" ]; then
        # Test syntax Python
        if python3 -m py_compile "$script" 2>/dev/null; then
            show_status "$script" "OK" "Script ada dan syntax valid"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            show_status "$script" "ERROR" "Script ada tapi syntax error"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        show_status "$script" "ERROR" "Script tidak ditemukan"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
done

echo ""

# 5. VALIDASI INTEGRASI WAZUH
echo -e "${BLUE}5. VALIDASI INTEGRASI WAZUH${NC}"
echo "----------------------------------------"

if [ -d "/var/ossec" ]; then
    show_status "Wazuh Directory" "OK" "Direktori Wazuh tersedia"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    
    if [ -f "/var/ossec/etc/ossec.conf" ]; then
        if grep -q "soc_incident_response" "/var/ossec/etc/ossec.conf" 2>/dev/null; then
            show_status "Wazuh Integration" "OK" "Script terintegrasi dengan Wazuh"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            show_status "Wazuh Integration" "WARNING" "Script belum terintegrasi dengan Wazuh"
            TESTS_WARNING=$((TESTS_WARNING + 1))
        fi
    else
        show_status "Wazuh Config" "WARNING" "Konfigurasi Wazuh tidak ditemukan"
        TESTS_WARNING=$((TESTS_WARNING + 1))
    fi
else
    show_status "Wazuh" "WARNING" "Wazuh tidak terinstall"
    TESTS_WARNING=$((TESTS_WARNING + 1))
fi

echo ""

# 6. VALIDASI DIREKTORI SISTEM
echo -e "${BLUE}6. VALIDASI DIREKTORI SISTEM${NC}"
echo "----------------------------------------"

# Load config untuk mendapatkan path
if [ -f "/etc/soc-config/config.conf" ]; then
    source "/etc/soc-config/config.conf"
    
    DIRS=("$WEB_DIR" "$BACKUP_DIR" "$QUARANTINE_DIR" "$LOG_DIR")
    DIR_NAMES=("Web Directory" "Backup Directory" "Quarantine Directory" "Log Directory")
    
    for i in "${!DIRS[@]}"; do
        if [ -d "${DIRS[$i]}" ]; then
            show_status "${DIR_NAMES[$i]}" "OK" "Direktori tersedia: ${DIRS[$i]}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            show_status "${DIR_NAMES[$i]}" "WARNING" "Direktori tidak tersedia: ${DIRS[$i]}"
            TESTS_WARNING=$((TESTS_WARNING + 1))
        fi
    done
else
    show_status "Directory Check" "ERROR" "Tidak dapat memuat konfigurasi"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""

# 7. TEST FUNGSIONALITAS
echo -e "${BLUE}7. TEST FUNGSIONALITAS${NC}"
echo "----------------------------------------"

# Test main script
if [ -f "soc_incident_response.py" ]; then
    # Test help command
    if python3 soc_incident_response.py --help >/dev/null 2>&1; then
        show_status "Main Script Help" "OK" "Command --help berfungsi"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        show_status "Main Script Help" "WARNING" "Command --help tidak berfungsi"
        TESTS_WARNING=$((TESTS_WARNING + 1))
    fi
    
    # Test status command
    if python3 soc_incident_response.py status >/dev/null 2>&1; then
        show_status "Main Script Status" "OK" "Command status berfungsi"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        show_status "Main Script Status" "WARNING" "Command status tidak berfungsi"
        TESTS_WARNING=$((TESTS_WARNING + 1))
    fi
else
    show_status "Main Script Test" "ERROR" "Script utama tidak ditemukan"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""

# 8. TEST INTEGRASI MODUL
echo -e "${BLUE}8. TEST INTEGRASI MODUL${NC}"
echo "----------------------------------------"

# Test import modul
if python3 -c "
import sys
sys.path.append('.')
try:
    import Deteksi
    import containment
    import eradication
    import restore
    import PostIA
    print('All modules imported successfully')
except ImportError as e:
    print(f'Import error: {e}')
    sys.exit(1)
" 2>/dev/null; then
    show_status "Module Import" "OK" "Semua modul dapat diimport"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    show_status "Module Import" "ERROR" "Gagal import beberapa modul"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""

# 9. RINGKASAN HASIL
echo -e "${BLUE}=================================================================${NC}"
echo -e "${BLUE}                      RINGKASAN HASIL                           ${NC}"
echo -e "${BLUE}=================================================================${NC}"
echo ""
echo -e "Total Tests: $((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))"
echo -e "${GREEN}✅ Passed: $TESTS_PASSED${NC}"
echo -e "${RED}❌ Failed: $TESTS_FAILED${NC}"
echo -e "${YELLOW}⚠️  Warning: $TESTS_WARNING${NC}"
echo ""

# Hitung persentase keberhasilan
TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))
if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$((TESTS_PASSED * 100 / TOTAL_TESTS))
    echo -e "Success Rate: ${SUCCESS_RATE}%"
    
    if [ $SUCCESS_RATE -ge 90 ]; then
        echo -e "${GREEN}🎉 Sistem siap untuk production!${NC}"
    elif [ $SUCCESS_RATE -ge 70 ]; then
        echo -e "${YELLOW}⚠️  Sistem memerlukan perbaikan minor${NC}"
    else
        echo -e "${RED}🚨 Sistem memerlukan perbaikan signifikan${NC}"
    fi
fi

echo ""
echo -e "${BLUE}=================================================================${NC}"

# Exit code berdasarkan hasil
if [ $TESTS_FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi
