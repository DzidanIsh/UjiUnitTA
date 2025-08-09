#!/bin/bash

# ==============================================================================
# SOC INCIDENT RESPONSE SYSTEM - UNIFIED INSTALLATION SCRIPT
# ==============================================================================
# Script Instalasi Terpadu Sistem SOC (Security Operations Center)
# Berdasarkan NIST 800-61r2 Incident Response Life Cycle Framework
# Components: Wazuh Server/Agent, MISP, YARA, ClamAV, Monitoring Server, Custom Scripts
# ------------------------------------------------------------------------------------

set -e  # Exit on any error

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# ==============================================================================
# ENHANCED LOGGING SYSTEM
# ==============================================================================

# Definisikan path file log terpusat dengan timestamp
LOG_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="/var/log/soc_unified_install_${LOG_TIMESTAMP}.log"
LOG_DIR="/var/log/soc-installation"

# Buat direktori log jika belum ada
mkdir -p "$LOG_DIR"

# Inisialisasi file log dengan header lengkap
cat > "$LOG_FILE" << EOF
===============================================================================
SOC UNIFIED INSTALLATION LOG
===============================================================================
Installation Started: $(date '+%Y-%m-%d %H:%M:%S')
Script Version: 3.0 (Unified)
Script Path: $SCRIPT_DIR
Log File: $LOG_FILE
System Info: $(uname -a)
User: $(whoami)
Working Directory: $(pwd)
===============================================================================

EOF

chmod 640 "$LOG_FILE"

# ==============================================================================
# FUNCTION DEFINITIONS - SEMUA FUNGSI HARUS DIDEFINISIKAN DI SINI
# ==============================================================================

# Fungsi logging yang ditingkatkan
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$level] $timestamp - $message"
    
    # Tulis ke file log
    echo "$log_entry" >> "$LOG_FILE"
    
    # Tampilkan ke console dengan warna
    case $level in
        "INFO")
            echo -e "\e[34m[INFO]\e[0m $timestamp - $message"
            ;;
        "SUCCESS")
            echo -e "\e[32m[SUCCESS]\e[0m $timestamp - $message"
            ;;
        "WARNING")
            echo -e "\e[33m[WARNING]\e[0m $timestamp - $message"
            ;;
        "ERROR")
            echo -e "\e[31m[ERROR]\e[0m $timestamp - $message" >&2
            ;;
        "DEBUG")
            if [[ "${DEBUG_MODE:-false}" == "true" ]]; then
                echo -e "\e[36m[DEBUG]\e[0m $timestamp - $message"
            fi
            echo "$log_entry" >> "$LOG_FILE"
            ;;
    esac
}

# Fungsi untuk menampilkan pesan error dan keluar
error_exit() {
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    log_message "ERROR" "$msg"
    echo "===============================================================================" >> "$LOG_FILE"
    echo "INSTALLATION FAILED at $timestamp" >> "$LOG_FILE"
    echo "Last Error: $msg" >> "$LOG_FILE"
    echo "===============================================================================" >> "$LOG_FILE"
    
    # Simpan log ke direktori log dengan nama yang mudah ditemukan
    cp "$LOG_FILE" "$LOG_DIR/installation_failed_${LOG_TIMESTAMP}.log"
    
    exit 1
}

# Fungsi untuk menampilkan pesan sukses
success_msg() {
    log_message "SUCCESS" "$1"
}

# Fungsi untuk menampilkan pesan info
info_msg() {
    log_message "INFO" "$1"
}

# Fungsi untuk menampilkan pesan peringatan
warning_msg() {
    log_message "WARNING" "$1"
}

# Fungsi untuk debug (hanya tampil jika DEBUG_MODE=true)
debug_msg() {
    log_message "DEBUG" "$1"
}

# Fungsi untuk mencatat command yang dijalankan
log_command() {
    local cmd="$1"
    debug_msg "Executing command: $cmd"
    echo "[COMMAND] $(date '+%Y-%m-%d %H:%M:%S') - $cmd" >> "$LOG_FILE"
}

# Fungsi untuk mencatat output command
log_output() {
    local output="$1"
    echo "[OUTPUT] $(date '+%Y-%m-%d %H:%M:%S') - $output" >> "$LOG_FILE"
}

# Fungsi untuk mencatat error command
log_error() {
    local error="$1"
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $error" >> "$LOG_FILE"
}

# Fungsi untuk menjalankan command dengan logging
run_command() {
    local cmd="$1"
    local description="${2:-Executing command}"
    
    info_msg "$description"
    log_command "$cmd"
    
    if output=$(eval "$cmd" 2>&1); then
        log_output "$output"
        return 0
    else
        local exit_code=$?
        log_error "$output"
        error_exit "Command failed with exit code $exit_code: $cmd"
    fi
}

# Fungsi untuk menjalankan command dengan output yang tidak di-log (untuk password input)
run_command_silent() {
    local cmd="$1"
    local description="${2:-Executing command}"
    
    info_msg "$description"
    log_command "$cmd"
    
    if eval "$cmd" >/dev/null 2>&1; then
        return 0
    else
        local exit_code=$?
        error_exit "Command failed with exit code $exit_code: $cmd"
    fi
}

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

# Fungsi untuk memvalidasi IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a ip_parts <<< "$ip"
        for part in "${ip_parts[@]}"; do
            if [ "$part" -gt 255 ] || [ "$part" -lt 0 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Fungsi untuk memvalidasi path
validate_path() {
    local path=$1
    if [[ "$path" =~ ^/ ]]; then
        return 0
    fi
    return 1
}

# Fungsi untuk memeriksa apakah script dijalankan sebagai root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "Script ini harus dijalankan sebagai root"
    fi
}

# Fungsi untuk memeriksa koneksi internet
check_internet() {
    info_msg "Memeriksa koneksi internet..."
    if ! ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
        error_exit "Tidak ada koneksi internet. Pastikan sistem terhubung ke internet."
    fi
    success_msg "Koneksi internet tersedia"
}

# Fungsi untuk memeriksa sistem operasi
check_os() {
    info_msg "Memeriksa sistem operasi..."
    
    if [[ -f /etc/debian_version ]]; then
        OS_TYPE="debian"
        OS_VERSION=$(cat /etc/debian_version)
        info_msg "Sistem operasi terdeteksi: Debian/Ubuntu ($OS_VERSION)"
    elif [[ -f /etc/redhat-release ]]; then
        OS_TYPE="redhat"
        OS_VERSION=$(cat /etc/redhat-release)
        info_msg "Sistem operasi terdeteksi: RHEL/CentOS/Fedora ($OS_VERSION)"
    else
        warning_msg "Sistem operasi tidak dikenali. Script mungkin tidak berfungsi dengan baik."
        OS_TYPE="unknown"
    fi
}

# ==============================================================================
# FUNGSI INSTALASI WAZUH
# ==============================================================================

# Fungsi untuk mendapatkan interface utama
get_main_interface() {
    # Mendapatkan interface default yang terhubung ke internet
    local main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$main_interface" ]; then
        # Fallback: mengambil interface pertama yang aktif (bukan lo)
        main_interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi
    echo "$main_interface"
}

# Fungsi untuk mendapatkan gateway
get_default_gateway() {
    local gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# Fungsi untuk mendapatkan IP yang tersedia
get_available_ip() {
    local interface=$1
    local gateway=$2
    
    # Mendapatkan network prefix dari gateway
    local network_prefix=$(echo "$gateway" | cut -d. -f1-3)
    
    # Mencoba beberapa IP dalam range yang sama dengan gateway
    for i in {10..20}; do
        local test_ip="${network_prefix}.$i"
        if ! ping -c1 -W1 "$test_ip" &>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # Fallback ke IP default jika tidak ada yang tersedia
    echo "${network_prefix}.10"
}

# Fungsi untuk konfigurasi IP Statis
configure_static_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    local gateway=$4
    local dns1=$5
    local dns2=$6

    info_msg "Menerapkan konfigurasi IP statis: $ip pada interface $interface"

    # Buat direktori netplan jika belum ada
    mkdir -p /etc/netplan

    # Backup file konfigurasi network yang ada
    if [ -f "/etc/netplan/00-installer-config.yaml" ]; then
        cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.backup
    fi

    # Buat konfigurasi netplan baru dengan format yang benar
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${interface}:
      dhcp4: false
      addresses:
        - ${ip}/${netmask}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns1}, ${dns2}]
EOF

    # Set permission yang benar
    chown root:root /etc/netplan/00-installer-config.yaml
    chmod 0600 /etc/netplan/00-installer-config.yaml

    # Generate dan terapkan konfigurasi
    netplan generate

    # Terapkan konfigurasi dengan penanganan error
    if ! netplan apply; then
        warning_msg "Mencoba menerapkan konfigurasi dalam mode debug..."
        netplan --debug apply
    fi

    # Tunggu sebentar untuk interface up
    sleep 5

    # Verifikasi koneksi
    if ping -c 1 ${gateway} > /dev/null 2>&1; then
        success_msg "Konfigurasi IP statis berhasil diterapkan"
        return 0
    else
        error_exit "Gagal menerapkan konfigurasi IP statis"
        if [ -f "/etc/netplan/00-installer-config.yaml.backup" ]; then
            mv /etc/netplan/00-installer-config.yaml.backup /etc/netplan/00-installer-config.yaml
            chmod 0600 /etc/netplan/00-installer-config.yaml
            netplan apply
        fi
        return 1
    fi
}

# Fungsi untuk memeriksa persyaratan sistem Wazuh
check_wazuh_system_requirements() {
    info_msg "Memeriksa persyaratan sistem untuk Wazuh..."
    
    # Periksa RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 4096 ]; then
        warning_msg "RAM kurang dari 4GB. Wazuh membutuhkan minimal 4GB RAM"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Periksa disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        warning_msg "Ruang disk kurang dari 20GB. Wazuh membutuhkan minimal 20GB free space"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Fungsi untuk menangani error Wazuh
handle_wazuh_error() {
    local error_msg="$1"
    error_exit "Wazuh Error: $error_msg"
}

# Fungsi untuk generate perintah instalasi agent Wazuh
generate_wazuh_agent_command() {
    local server_ip=$1
    local WAZUH_VERSION="4.7.5"
    local ARCHITECTURE="amd64"

    info_msg "Membuat generator perintah instalasi Wazuh Agent"
    echo "IP Server Wazuh: $server_ip"

    # Input nama agent
    echo "Masukkan nomor atau nama untuk agent (default: ubuntu-agent):"
    read agent_name
    if [ -z "$agent_name" ]; then
        agent_name="ubuntu-agent"
    fi

    # Generate perintah instalasi
    local install_command="wget https://packages.wazuh.com/${WAZUH_VERSION%.*}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb && sudo WAZUH_MANAGER='${server_ip}' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='${agent_name}' dpkg -i ./wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb"

    # Simpan perintah ke file
    cat > /root/install_wazuh_agent.sh << EOF
#!/bin/bash

# Script instalasi Wazuh Agent
# Generated pada: $(date)
# Server: $server_ip
# Agent Name: $agent_name

$install_command

# Start Wazuh Agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Check status
sudo systemctl status wazuh-agent
EOF

    chmod +x /root/install_wazuh_agent.sh

    success_msg "Script instalasi agent telah dibuat: /root/install_wazuh_agent.sh"
    echo "Perintah instalasi untuk agent:"
    echo "$install_command"
    echo "Atau gunakan script yang telah dibuat:"
    echo "scp /root/install_wazuh_agent.sh user@agent-ip:~/"
    echo "ssh user@agent-ip 'sudo bash ~/install_wazuh_agent.sh'"

    # Tampilkan ringkasan
    echo "Ringkasan Agent Installation:"
    echo "1. Server IP: $server_ip"
    echo "2. Agent Name: $agent_name"
    echo "3. Wazuh Version: $WAZUH_VERSION"
    echo "4. Architecture: $ARCHITECTURE"
    echo "5. Agent Group: default"
}

# Fungsi untuk instalasi Wazuh
install_wazuh() {
    info_msg "Memulai instalasi Wazuh..."
    
    # Deteksi otomatis konfigurasi jaringan
    info_msg "Mendeteksi konfigurasi jaringan..."

    # Deteksi interface utama
    INTERFACE=$(get_main_interface)
    success_msg "Interface terdeteksi: $INTERFACE"

    # Deteksi gateway
    GATEWAY=$(get_default_gateway)
    if [ -z "$GATEWAY" ]; then
        warning_msg "Tidak dapat mendeteksi gateway. Menggunakan default gateway"
        GATEWAY="192.168.1.1"
    fi
    success_msg "Gateway terdeteksi: $GATEWAY"

    # Set IP statis yang tersedia
    STATIC_IP=$(get_available_ip "$INTERFACE" "$GATEWAY")
    success_msg "IP statis yang akan digunakan: $STATIC_IP"

    # Set konfigurasi default
    NETMASK="24"
    DNS1="8.8.8.8"
    DNS2="8.8.4.4"

    # Periksa persyaratan sistem
    check_wazuh_system_requirements

    # Terapkan konfigurasi IP statis
    info_msg "Menerapkan konfigurasi IP statis..."
    configure_static_ip "$STATIC_IP" "$INTERFACE" "$NETMASK" "$GATEWAY" "$DNS1" "$DNS2"

    # Buat direktori untuk menyimpan file instalasi
    INSTALL_DIR="/root/wazuh-install-files"
    mkdir -p ${INSTALL_DIR}
    cd ${INSTALL_DIR}

    # Download Wazuh installer
    info_msg "Mengunduh Wazuh installer..."
    if ! curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh; then
        handle_wazuh_error "Gagal mengunduh installer Wazuh"
    fi

    chmod +x wazuh-install.sh

    # Membuat config.yml
    cat > config.yml << EOF
nodes:
  indexer:
    - name: node-1
      ip: ${STATIC_IP}
      role: master
  server:
    - name: wazuh-1
      ip: ${STATIC_IP}
  dashboard:
    - name: dashboard
      ip: ${STATIC_IP}
EOF

    # Buat direktori untuk menyimpan kredensial
    CRED_DIR="/root/wazuh-credentials"
    mkdir -p ${CRED_DIR}
    chmod 700 ${CRED_DIR}

    # Menjalankan instalasi dengan penanganan error
    success_msg "Memulai instalasi Wazuh..."

    # Generate config files
    if ! ./wazuh-install.sh --generate-config-files; then
        handle_wazuh_error "Gagal generate config files"
    fi
    success_msg "Konfigurasi berhasil di-generate"

    # Install dan start Wazuh indexer
    if ! ./wazuh-install.sh --wazuh-indexer node-1; then
        handle_wazuh_error "Gagal instalasi wazuh indexer"
    fi
    success_msg "Wazuh indexer berhasil diinstal"

    # Tunggu indexer siap
    info_msg "Menunggu Wazuh indexer siap..."
    sleep 30

    # Start cluster
    if ! ./wazuh-install.sh --start-cluster; then
        handle_wazuh_error "Gagal memulai cluster"
    fi
    success_msg "Cluster berhasil dimulai"

    # Simpan password
    info_msg "Menyimpan kredensial..."
    tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > ${CRED_DIR}/wazuh-passwords-full.txt
    chmod 600 ${CRED_DIR}/wazuh-passwords-full.txt

    # Install Wazuh server
    if ! ./wazuh-install.sh --wazuh-server wazuh-1; then
        handle_wazuh_error "Gagal instalasi wazuh server"
    fi
    success_msg "Wazuh server berhasil diinstal"

    # Tunggu server siap
    info_msg "Menunggu Wazuh server siap..."
    sleep 30

    # Install Wazuh dashboard
    if ! ./wazuh-install.sh --wazuh-dashboard dashboard; then
        handle_wazuh_error "Gagal instalasi wazuh dashboard"
    fi
    success_msg "Wazuh dashboard berhasil diinstal"

    # Ekstrak dan simpan password spesifik
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "admin" > ${CRED_DIR}/admin-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "wazuh" > ${CRED_DIR}/wazuh-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "kibana" > ${CRED_DIR}/kibana-passwords.txt

    # Buat file rangkuman kredensial
    cat > ${CRED_DIR}/credentials-summary.txt << EOF
Wazuh Credentials Summary
========================
Tanggal Instalasi: $(date)
IP Server: ${STATIC_IP}

Lokasi File Kredensial:
- Password Lengkap: ${CRED_DIR}/wazuh-passwords-full.txt
- Password Admin: ${CRED_DIR}/admin-passwords.txt
- Password Wazuh: ${CRED_DIR}/wazuh-passwords.txt
- Password Kibana: ${CRED_DIR}/kibana-passwords.txt

Akses Dashboard: https://${STATIC_IP}
Default username: admin

Note: 
- Simpan file ini di tempat yang aman
- Ganti password default setelah login pertama
- Backup folder ${CRED_DIR} secara berkala
EOF

    # Set permission untuk file kredensial
    chmod 600 ${CRED_DIR}/*
    chown -R root:root ${CRED_DIR}

    # Tambahkan entri ke /etc/hosts
    echo "${STATIC_IP} node-1 wazuh-1 dashboard" >> /etc/hosts

    # Periksa status layanan
    info_msg "Memeriksa status layanan..."
    services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            success_msg "Service $service berjalan dengan baik"
        else
            warning_msg "Service $service tidak berjalan"
            systemctl status $service
            info_msg "Mencoba restart service ${service}..."
            systemctl restart $service
            sleep 5
            if systemctl is-active --quiet $service; then
                success_msg "Service $service berhasil direstart"
            else
                warning_msg "Service $service masih bermasalah"
            fi
        fi
    done

    # Simpan informasi konfigurasi
    cat > /root/wazuh-info.txt << EOF
Konfigurasi Wazuh:
=================
IP Address: ${STATIC_IP}
Interface: ${INTERFACE}
Netmask: ${NETMASK}
Gateway: ${GATEWAY}
DNS1: ${DNS1}
DNS2: ${DNS2}

Dashboard URL: https://${STATIC_IP}

Lokasi File Kredensial: ${CRED_DIR}
EOF

    success_msg "Instalasi Wazuh selesai!"
    echo "Anda dapat mengakses dashboard di: https://${STATIC_IP}"
    echo "Kredensial tersimpan di: ${CRED_DIR}"
    echo "Informasi konfigurasi tersimpan di: /root/wazuh-info.txt"

    # Generate script instalasi agent
    info_msg "Membuat script instalasi untuk Wazuh Agent..."
    generate_wazuh_agent_command "${STATIC_IP}"

    success_msg "Proses instalasi dan konfigurasi Wazuh selesai!"
    
    # Return ke direktori asal
    cd "$SCRIPT_DIR"
}

# ==============================================================================
# FUNGSI INSTALASI MISP
# ==============================================================================

# Function to check MISP dependencies
check_misp_dependencies() {
    info_msg "Checking MISP dependencies..."
    if ! command -v docker &> /dev/null; then
        error_exit "Error: 'docker' is not installed. Please install Docker first."
    fi
    if ! command -v docker-compose &> /dev/null; then
        error_exit "Error: 'docker-compose' is not installed. Please install Docker Compose first."
    fi
    success_msg "MISP dependencies are satisfied."
}

# Function to wait for MISP to become available
wait_for_misp() {
    info_msg "Waiting for MISP to become available... This may take several minutes."
    until curl --output /dev/null --silent --head --fail --insecure https://localhost; do
        printf '.'
        sleep 5
    done
    success_msg "MISP is up and running!"
}

# Function to install and setup MISP
install_misp() {
    info_msg "Memulai instalasi MISP..."
    
    # MISP Configuration
    MISP_INSTALL_DIR="/opt/misp-docker"
    MISP_DOCKER_COMPOSE_URL="https://raw.githubusercontent.com/misp/misp-docker/main/docker-compose.yml"
    
    # Detail untuk pengguna API yang akan dibuat
    ORG_NAME="Wazuh-IR-Automation"
    USER_EMAIL_FOR_KEY="wazuh-automation@localhost.local"
    USER_COMMENT="API key for Wazuh Active Response integration"
    
    check_misp_dependencies
    
    # Periksa apakah kontainer MISP sudah berjalan
    MISP_CONTAINER_ID=$(docker ps -q --filter "name=misp-server")
    
    if [ -z "$MISP_CONTAINER_ID" ]; then
        info_msg "MISP container not found. Starting installation process..."
        
        # 1. Buat direktori instalasi
        info_msg "Creating installation directory at ${MISP_INSTALL_DIR}..."
        run_command "mkdir -p '$MISP_INSTALL_DIR'" "Creating MISP installation directory"
        cd "$MISP_INSTALL_DIR"
        
        # 2. Unduh file docker-compose.yml
        info_msg "Downloading latest misp-docker docker-compose.yml..."
        run_command "curl -o docker-compose.yml '$MISP_DOCKER_COMPOSE_URL'" "Downloading MISP docker-compose file"
        
        # 3. Jalankan MISP menggunakan docker-compose
        info_msg "Starting MISP containers in detached mode (-d)..."
        run_command "docker-compose up -d" "Starting MISP containers"
        
        # 4. Tunggu hingga MISP benar-benar siap
        wait_for_misp
        
        success_msg "MISP installation completed successfully."
    else
        success_msg "MISP is already installed and running."
        # Pastikan kita berada di direktori yang benar untuk perintah exec
        cd "$MISP_INSTALL_DIR"
    fi
    
    # Pengambilan API Key
    info_msg "Attempting to create/retrieve API key for user '${USER_EMAIL_FOR_KEY}'..."
    
    # Dapatkan email admin default dari dalam kontainer
    ADMIN_EMAIL=$(docker-compose exec -T misp-server cat /var/www/MISP/app/Config/config.php | grep "'email' =>" | head -1 | sed "s/.*'email' => '\([^']*\)'.*/\1/")
    
    if [ -z "$ADMIN_EMAIL" ]; then
        warning_msg "Could not automatically determine admin email. Defaulting to 'admin@admin.test'."
        ADMIN_EMAIL="admin@admin.test"
    fi
    
    info_msg "Using admin email: ${ADMIN_EMAIL}"
    
    # Gunakan perintah 'cake' di dalam kontainer untuk membuat pengguna dan mendapatkan kuncinya
    API_KEY_OUTPUT=$(docker-compose exec -T misp-server \
        /var/www/MISP/app/Console/cake Admin setApiUser "$ADMIN_EMAIL" "$ORG_NAME" "$USER_EMAIL_FOR_KEY" "$USER_COMMENT")
    
    # Ekstrak kunci API dari output
    MISP_KEY=$(echo "$API_KEY_OUTPUT" | grep 'Auth key:' | awk '{print $3}')
    
    if [ -n "$MISP_KEY" ]; then
        success_msg "Successfully retrieved API Key!"
        echo "------------------------------------------------------------------"
        echo "Your MISP API Key is: $MISP_KEY"
        echo "------------------------------------------------------------------"
        echo "Simpan kunci ini di tempat yang aman. Anda akan membutuhkannya untuk"
        echo "mengkonfigurasi skrip integrasi Wazuh."
        
        # Update config.conf dengan API key yang baru
        if [ -f "/etc/soc-config/config.conf" ]; then
            sed -i "s/MISP_KEY=.*/MISP_KEY=\"$MISP_KEY\"/" /etc/soc-config/config.conf
            success_msg "MISP API Key berhasil diupdate di config.conf"
        fi
    else
        error_exit "Error: Failed to retrieve API Key."
        info_msg "Please check the logs using 'docker-compose logs -f' in '${MISP_INSTALL_DIR}'."
    fi
    
    success_msg "MISP setup completed successfully!"
}

# ==============================================================================
# FUNGSI INSTALASI SERVER MONITORING
# ==============================================================================

# Function to setup monitoring server (backup repository)
install_monitoring_server() {
    info_msg "Memulai instalasi Server Monitoring (Backup Repository)..."
    
    # Tentukan direktori untuk menyimpan backup
    info_msg "Menentukan direktori untuk menyimpan backup Git dan arsip dinamis..."
    read -r -p "Masukkan path direktori utama backup (default: /var/backup/web_backups): " MAIN_BACKUP_DIR
    MAIN_BACKUP_DIR=${MAIN_BACKUP_DIR:-/var/backup/web_backups}

    # Path untuk backup Git (repositori bare)
    GIT_BACKUP_SUBDIR="git_repo" # Nama subdirektori untuk Git
    ACTUAL_GIT_BACKUP_PATH="$MAIN_BACKUP_DIR/$GIT_BACKUP_SUBDIR"

    # Path untuk backup file dinamis (arsip .tar.gz)
    DYNAMIC_BACKUP_SUBDIR="dynamic_archives" # Nama subdirektori untuk arsip dinamis
    ACTUAL_DYNAMIC_BACKUP_PATH="$MAIN_BACKUP_DIR/$DYNAMIC_BACKUP_SUBDIR"

    # Buat direktori backup jika belum ada
    if [ ! -d "$ACTUAL_GIT_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup Git: $ACTUAL_GIT_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_GIT_BACKUP_PATH'" "Creating Git backup directory"
    fi
    if [ ! -d "$ACTUAL_DYNAMIC_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup dinamis: $ACTUAL_DYNAMIC_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_DYNAMIC_BACKUP_PATH'" "Creating dynamic backup directory"
    fi

    # Membuat pengguna khusus untuk backup
    echo ""
    info_msg "Pengaturan Pengguna Khusus untuk Menerima Backup"
    echo "----------------------------------------------------"
    read -r -p "Apakah Anda ingin membuat pengguna sistem khusus untuk menerima backup via SSH? (y/n, default: y): " CREATE_USER
    CREATE_USER=${CREATE_USER:-y}

    BACKUP_USER="" # Akan diisi jika CREATE_USER=y

    if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]]; then
        read -r -p "Masukkan nama pengguna untuk backup (default: webbackupuser): " INPUT_BACKUP_USER
        BACKUP_USER=${INPUT_BACKUP_USER:-webbackupuser}
        
        if id "$BACKUP_USER" &>/dev/null; then
            info_msg "Pengguna '$BACKUP_USER' sudah ada."
        else
            info_msg "Membuat pengguna '$BACKUP_USER'..."
            run_command "useradd -r -m -s /bin/bash '$BACKUP_USER'" "Creating backup user"
            success_msg "Pengguna '$BACKUP_USER' berhasil dibuat."
        fi
        
        info_msg "Mengatur kepemilikan direktori backup untuk pengguna '$BACKUP_USER'..."
        run_command "chown -R '$BACKUP_USER:$BACKUP_USER' '$MAIN_BACKUP_DIR'" "Setting ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting permissions of backup directory"

        # Inisialisasi repository Git bare
        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH'..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
            read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        
        # Mengatur SSH untuk pengguna backup
        USER_SSH_DIR="/home/$BACKUP_USER/.ssh"
        info_msg "Memastikan direktori SSH '$USER_SSH_DIR' dan 'authorized_keys' ada untuk pengguna '$BACKUP_USER'..."
        run_command "sudo -u '$BACKUP_USER' mkdir -p '$USER_SSH_DIR'" "Creating SSH directory for backup user"
        run_command "sudo -u '$BACKUP_USER' touch '$USER_SSH_DIR/authorized_keys'" "Creating authorized_keys file"
        run_command "sudo -u '$BACKUP_USER' chmod 700 '$USER_SSH_DIR'" "Setting SSH directory permissions"
        run_command "sudo -u '$BACKUP_USER' chmod 600 '$USER_SSH_DIR/authorized_keys'" "Setting authorized_keys permissions"
        success_msg "Setup direktori SSH untuk '$BACKUP_USER' selesai."
        
        echo ""
        info_msg "--- INSTRUKSI PENTING UNTUK SERVER WEB ---"
        echo "Untuk mengizinkan server web melakukan push backup ke server monitoring ini:"
        echo "1. Di SERVER WEB, pastikan Anda memiliki SSH key pair untuk user root (atau user yang menjalankan backup)."
        echo "   Kunci publiknya (biasanya di '/root/.ssh/id_rsa_web_backup.pub') perlu disalin."
        echo "2. Di SERVER MONITORING INI, tambahkan isi kunci publik tersebut ke dalam file:"
        echo "   $USER_SSH_DIR/authorized_keys"
        echo "3. Pastikan pengguna '$BACKUP_USER' adalah pemilik file tersebut dan memiliki izin yang benar (chmod 600)."
        echo "--------------------------------------------"

    else # Jika tidak membuat pengguna khusus, backup akan diterima oleh root
        BACKUP_USER="root" # Backup akan menggunakan root jika tidak ada user khusus
        warning_msg "PERINGATAN: Tidak ada pengguna khusus yang dibuat. Backup akan diterima sebagai pengguna 'root'. Ini kurang aman."
        info_msg "Pastikan direktori '$MAIN_BACKUP_DIR' dapat ditulis oleh root."
        run_command "chown -R 'root:root' '$MAIN_BACKUP_DIR'" "Setting root ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting root permissions of backup directory"

        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH' sebagai root..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
             read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository as root"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository as root"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        info_msg "SSH key dari server web perlu ditambahkan ke '/root/.ssh/authorized_keys' di server monitoring ini."
    fi

    # Konfigurasi Monitoring Server Ini Sendiri (Opsional)
    echo ""
    info_msg "Konfigurasi Monitoring untuk Server Backup Ini Sendiri (Opsional)"
    echo "-------------------------------------------------------------------"
    read -r -p "Apakah Anda ingin menginstal Wazuh Agent untuk memonitor server backup ini sendiri? (y/n, default: n): " INSTALL_WAZUH_AGENT_LOCAL
    INSTALL_WAZUH_AGENT_LOCAL=${INSTALL_WAZUH_AGENT_LOCAL:-n}

    if [[ "$INSTALL_WAZUH_AGENT_LOCAL" == "y" || "$INSTALL_WAZUH_AGENT_LOCAL" == "Y" ]]; then
        info_msg "Memulai instalasi Wazuh Agent untuk server backup ini..."
        
        if ! command -v apt-key &> /dev/null || ! command -v tee &> /dev/null ; then
            run_command "apt-get install -y gnupg apt-transport-https" "Installing gnupg and apt-transport-https"
        fi

        run_command "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg" "Importing Wazuh GPG key"
        run_command "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list" "Adding Wazuh repository"
        
        run_command "apt-get update -y" "Updating package list after adding Wazuh repository"
        run_command "apt-get install -y wazuh-agent" "Installing Wazuh Agent"
        
        read -r -p "Masukkan alamat IP Wazuh Manager untuk agent ini: " WAZUH_MANAGER_IP_FOR_AGENT
        while [[ -z "$WAZUH_MANAGER_IP_FOR_AGENT" ]]; do
            read -r -p "Alamat IP Wazuh Manager tidak boleh kosong. Masukkan IP: " WAZUH_MANAGER_IP_FOR_AGENT
        done
        
        # Konfigurasi Wazuh Agent (ossec.conf)
        run_command "sed -i 's|<address>MANAGER_IP</address>|<address>$WAZUH_MANAGER_IP_FOR_AGENT</address>|g' /var/ossec/etc/ossec.conf" "Configuring Wazuh Agent manager IP"
        
        run_command "systemctl daemon-reload" "Reloading systemd daemon"
        run_command "systemctl enable wazuh-agent" "Enabling Wazuh Agent service"
        run_command "systemctl restart wazuh-agent" "Starting Wazuh Agent service"
        
        success_msg "Wazuh Agent berhasil diinstal dan dikonfigurasi untuk memonitor server backup ini."
        info_msg "Pastikan untuk mendaftarkan agent ini di Wazuh Manager."
    else
        info_msg "Instalasi Wazuh Agent untuk server backup ini dilewati."
    fi

    # Konfigurasi Git Hooks untuk Notifikasi (opsional)
    echo ""
    info_msg "Konfigurasi Git Hook untuk Notifikasi Email (Opsional)"
    echo "---------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur notifikasi email setiap kali backup Git diterima? (y/n, default: n): " SETUP_NOTIFICATION
    SETUP_NOTIFICATION=${SETUP_NOTIFICATION:-n}

    if [[ "$SETUP_NOTIFICATION" == "y" || "$SETUP_NOTIFICATION" == "Y" ]]; then
        if ! command -v mail &> /dev/null; then
            info_msg "Command 'mail' (mailutils) tidak ditemukan. Menginstal..."
            run_command "apt-get install -y mailutils" "Installing mailutils for email notifications"
        fi

        if command -v mail &> /dev/null; then
            read -r -p "Masukkan alamat email untuk notifikasi: " NOTIFY_EMAIL
            while [[ -z "$NOTIFY_EMAIL" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " NOTIFY_EMAIL
            done
            
            HOOK_DIR="$ACTUAL_GIT_BACKUP_PATH/hooks"
            HOOK_FILE="$HOOK_DIR/post-receive"

            info_msg "Membuat direktori hook $HOOK_DIR jika belum ada..."
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "sudo -u '$BACKUP_USER' mkdir -p '$HOOK_DIR'" "Creating hook directory as backup user"
            else
                run_command "mkdir -p '$HOOK_DIR'" "Creating hook directory"
            fi

            info_msg "Membuat skrip post-receive hook di $HOOK_FILE..."
            cat > "$HOOK_FILE" << EOF_HOOK
#!/bin/bash
# Git hook untuk mengirim notifikasi email saat menerima backup baru

REPO_NAME="\$(basename "\$(pwd)")"
COMMIT_INFO=\$(git log -1 --pretty=format:"%h - %an, %ar : %s")
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=\$(date +"%Y-%m-%d %H:%M:%S")

mail -s "Backup GIT Baru Diterima di \$SERVER_HOSTNAME untuk \$REPO_NAME" "$NOTIFY_EMAIL" << EOM_MAIL
Backup Git baru telah diterima di server monitoring: \$SERVER_HOSTNAME

Repository Path: \$(pwd)
Timestamp: \$TIMESTAMP
Commit Terakhir: \$COMMIT_INFO

Pesan ini dikirim otomatis dari hook post-receive.
EOM_MAIL
EOF_HOOK

            run_command "chmod +x '$HOOK_FILE'" "Making hook file executable"
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "chown '$BACKUP_USER:$BACKUP_USER' '$HOOK_FILE'" "Setting hook file ownership to backup user"
                info_msg "Kepemilikan hook diatur ke $BACKUP_USER."
            fi
            success_msg "Notifikasi email untuk backup Git baru telah dikonfigurasi di $HOOK_FILE."
            info_msg "Pastikan MTA (seperti Postfix atau ssmtp) terkonfigurasi di server ini agar perintah 'mail' berfungsi."
        else
            warning_msg "Gagal menginstal atau menemukan 'mail'. Notifikasi email dilewati."
        fi
    fi

    # Monitoring disk space untuk MAIN_BACKUP_DIR (opsional)
    echo ""
    info_msg "Monitoring Disk Space untuk Direktori Backup (Opsional)"
    echo "-----------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur monitoring disk space untuk '$MAIN_BACKUP_DIR'? (y/n, default: y): " SETUP_DISK_MONITORING
    SETUP_DISK_MONITORING=${SETUP_DISK_MONITORING:-y}

    if [[ "$SETUP_DISK_MONITORING" == "y" || "$SETUP_DISK_MONITORING" == "Y" ]]; then
        if ! command -v mail &> /dev/null && ! command -v mailx &> /dev/null ; then
            info_msg "Command 'mail' atau 'mailx' tidak ditemukan. Menginstal mailutils..."
            run_command "apt-get install -y mailutils" "Installing mailutils for disk monitoring"
        fi

        if command -v mail &> /dev/null || command -v mailx &> /dev/null ; then
            MONITOR_SCRIPT_PATH="/usr/local/bin/monitor_backup_disk_space.sh"
            info_msg "Membuat skrip monitoring disk di $MONITOR_SCRIPT_PATH..."

            cat > "$MONITOR_SCRIPT_PATH" << EOF_DISK_MON
#!/bin/bash
# Skrip untuk memonitor penggunaan disk direktori backup

TARGET_BACKUP_DIR="\$1"
USAGE_THRESHOLD="\$2" # Persentase, misal 80
EMAIL_RECIPIENT="\$3"
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
LOG_FILE="/var/log/backup_disk_monitor.log"
MAIL_COMMAND=\$(command -v mail || command -v mailx)

if [ -z "\$MAIL_COMMAND" ]; then
    echo "[\$(date)] Error: Perintah mail/mailx tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

if [ ! -d "\$TARGET_BACKUP_DIR" ]; then
    echo "[\$(date)] Error: Direktori backup '\$TARGET_BACKUP_DIR' tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

CURRENT_USAGE=\$(df "\$TARGET_BACKUP_DIR" | awk 'NR==2 {print \$5}' | sed 's/%//')

if [ -z "\$CURRENT_USAGE" ]; then
    echo "[\$(date)] Error: Tidak dapat mengambil info penggunaan disk untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
    exit 1
fi

if [ "\$CURRENT_USAGE" -gt "\$USAGE_THRESHOLD" ]; then
    SUBJECT="[PERINGATAN] Disk Backup di \$SERVER_HOSTNAME Hampir Penuh (\$CURRENT_USAGE%)"
    MESSAGE="Penggunaan disk pada direktori backup '\$TARGET_BACKUP_DIR' di server \$SERVER_HOSTNAME telah mencapai \$CURRENT_USAGE% (Threshold: \$USAGE_THRESHOLD%).\n\nDetail Penggunaan Disk:\n\$(df -h "\$TARGET_BACKUP_DIR")\n\nHarap segera periksa dan kosongkan ruang jika perlu."
    
    echo -e "\$MESSAGE" | \$MAIL_COMMAND -s "\$SUBJECT" "\$EMAIL_RECIPIENT"
    echo "[\$(date)] Peringatan Terkirim: Penggunaan disk \$CURRENT_USAGE% melebihi threshold \$USAGE_THRESHOLD% untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
else
    echo "[\$(date)] Info: Penggunaan disk \$CURRENT_USAGE% untuk '\$TARGET_BACKUP_DIR' masih di bawah threshold \$USAGE_THRESHOLD%." >> "\$LOG_FILE"
fi
exit 0
EOF_DISK_MON
            run_command "chmod +x '$MONITOR_SCRIPT_PATH'" "Making disk monitoring script executable"
            success_msg "Skrip monitoring disk $MONITOR_SCRIPT_PATH berhasil dibuat."

            read -r -p "Masukkan threshold penggunaan disk dalam persen (misal 80, default: 80): " DISK_THRESHOLD_INPUT
            DISK_THRESHOLD_INPUT=${DISK_THRESHOLD_INPUT:-80}
            read -r -p "Masukkan alamat email untuk notifikasi disk space: " DISK_EMAIL_INPUT
            while [[ -z "$DISK_EMAIL_INPUT" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " DISK_EMAIL_INPUT
            done
            
            CRON_DISK_MON_ENTRY="0 7 * * * $MONITOR_SCRIPT_PATH \"$MAIN_BACKUP_DIR\" \"$DISK_THRESHOLD_INPUT\" \"$DISK_EMAIL_INPUT\""
            
            # Tambahkan ke crontab root
            run_command "(crontab -l 2>/dev/null | grep -vF '$MONITOR_SCRIPT_PATH'; echo '$CRON_DISK_MON_ENTRY') | crontab -" "Adding disk monitoring to crontab"
            success_msg "Monitoring disk space untuk direktori backup '$MAIN_BACKUP_DIR' telah diatur via cron."
            info_msg "Log monitoring disk akan ada di /var/log/backup_disk_monitor.log"
        else
            warning_msg "Gagal menginstal atau menemukan 'mail/mailx'. Monitoring disk space dilewati."
        fi
    fi

    SERVER_IP_ADDRESS=$(hostname -I | awk '{print $1}') # Ambil IP utama

    echo ""
    echo "================================================================="
    echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
    echo "================================================================="
    echo ""
    echo "Informasi Penting untuk Konfigurasi Server Web:"
    echo "----------------------------------------------"
    echo "IP Server Monitoring Ini: ${SERVER_IP_ADDRESS:-Mohon periksa manual}"
    echo "Pengguna SSH untuk Backup: $BACKUP_USER"
    echo "Path Tujuan Backup Git: $ACTUAL_GIT_BACKUP_PATH"
    echo "Path Tujuan Backup Dinamis (arsip): $ACTUAL_DYNAMIC_BACKUP_PATH"
    echo ""
    echo "Contoh Perintah di Server Web untuk Menambahkan Remote Git:"
    echo "   git remote add monitoring $BACKUP_USER@${SERVER_IP_ADDRESS:-<IP_SERVER_MONITORING>}:$ACTUAL_GIT_BACKUP_PATH"
    echo ""
    echo "CATATAN PENTING:"
    echo "- Format URL Git SSH yang disarankan: '$BACKUP_USER@<IP_SERVER_MONITORING>:$ACTUAL_GIT_BACKUP_PATH' (gunakan path absolut)."
    echo "- Pastikan kunci SSH publik dari server web (user root atau yang menjalankan backup) telah ditambahkan ke:"
    echo "  '/home/$BACKUP_USER/.ssh/authorized_keys' (jika $BACKUP_USER dibuat) atau '/root/.ssh/authorized_keys' (jika tidak ada user khusus) di server monitoring ini."
    echo "- Pastikan direktori '$ACTUAL_DYNAMIC_BACKUP_PATH' dapat ditulis oleh '$BACKUP_USER' (atau root) melalui rsync/scp."
    echo ""
    echo "Server monitoring ini sekarang siap menerima backup."
    echo "================================================================="
}

# ==============================================================================
# FUNGSI KONFIGURASI SOC
# ==============================================================================

# Function to collect user input for configuration
collect_user_config() {
    info_msg "Mengumpulkan konfigurasi dari user..."
    
    # Web directory
    read -r -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
    WEB_DIR=${WEB_DIR:-/var/www/html}
    
    # Backup directory
    read -r -p "Masukkan path direktori backup (default: /var/soc-backup): " BACKUP_DIR
    BACKUP_DIR=${BACKUP_DIR:-/var/soc-backup}
    
    # Quarantine directory
    read -r -p "Masukkan path direktori karantina (default: /var/soc-quarantine): " QUARANTINE_DIR
    QUARANTINE_DIR=${QUARANTINE_DIR:-/var/soc-quarantine}
    
    # Log directory
    read -r -p "Masukkan path direktori log (default: /var/log/soc-incident-response): " LOG_DIR
    LOG_DIR=${LOG_DIR:-/var/log/soc-incident-response}
    
    # Wazuh alerts file
    read -r -p "Masukkan path file alerts Wazuh (default: /var/ossec/logs/alerts/alerts.json): " WAZUH_ALERTS_FILE
    WAZUH_ALERTS_FILE=${WAZUH_ALERTS_FILE:-/var/ossec/logs/alerts/alerts.json}
    
    # Rule IDs
    read -r -p "Masukkan Rule IDs untuk defacement (default: 550,554,5501,5502,5503,5504,100001,100002): " DEFACE_RULE_IDS
    DEFACE_RULE_IDS=${DEFACE_RULE_IDS:-550,554,5501,5502,5503,5504,100001,100002}
    
    read -r -p "Masukkan Rule IDs untuk serangan (default: 5710,5712,5715,5760,100003,100004): " ATTACK_RULE_IDS
    ATTACK_RULE_IDS=${ATTACK_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk eradication (default: 5710,5712,5715,5760,100003,100004): " ERADICATION_RULE_IDS
    ERADICATION_RULE_IDS=${ERADICATION_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk restore (default: 100010,100011,100012): " RESTORE_RULE_IDS
    RESTORE_RULE_IDS=${RESTORE_RULE_IDS:-100010,100011,100012}
    
    # MISP Configuration
    read -r -p "Masukkan URL MISP (default: https://192.168.28.135): " MISP_URL
    MISP_URL=${MISP_URL:-https://192.168.28.135}
    
    read -r -p "Masukkan API Key MISP: " MISP_KEY
    if [[ -z "$MISP_KEY" ]]; then
        MISP_KEY="XweOnEWOtWFmIbW585H2m03R3SIZRmIKxrza73WB"
        warning_msg "Menggunakan API Key default MISP"
    fi
    
    read -r -p "Verifikasi sertifikat MISP? (y/n, default: n): " MISP_VERIFY_CERT
    if [[ "$MISP_VERIFY_CERT" =~ ^[Yy]$ ]]; then
        MISP_VERIFY_CERT="true"
    else
        MISP_VERIFY_CERT="false"
    fi
    
    # Monitoring server
    while true; do
        read -r -p "Masukkan IP server monitoring (default: 192.168.1.100): " MONITORING_SERVER
        MONITORING_SERVER=${MONITORING_SERVER:-192.168.1.100}
        if validate_ip "$MONITORING_SERVER"; then
            break
        else
            warning_msg "IP address tidak valid. Silakan coba lagi."
        fi
    done
    
    read -r -p "Masukkan username server monitoring (default: soc-backup): " MONITORING_USER
    MONITORING_USER=${MONITORING_USER:-soc-backup}
    
    read -s -p "Masukkan password server monitoring: " MONITORING_PASSWORD
    echo
    
    # Backup paths
    read -r -p "Masukkan path backup remote (default: /home/soc-backup/backups): " REMOTE_BACKUP_PATH
    REMOTE_BACKUP_PATH=${REMOTE_BACKUP_PATH:-/home/soc-backup/backups}
    
    # Web server user/group
    read -r -p "Masukkan user web server (default: www-data): " WEB_SERVER_USER
    WEB_SERVER_USER=${WEB_SERVER_USER:-www-data}
    
    read -r -p "Masukkan group web server (default: www-data): " WEB_SERVER_GROUP
    WEB_SERVER_GROUP=${WEB_SERVER_GROUP:-www-data}
    
    # Password untuk restore
    read -s -p "Masukkan password untuk restore (minimal 12 karakter): " RESTORE_PASSWORD
    echo
    if [[ ${#RESTORE_PASSWORD} -lt 12 ]]; then
        error_exit "Password harus minimal 12 karakter"
    fi
    ENCODED_PASSWORD=$(echo -n "$RESTORE_PASSWORD" | base64)
    
    success_msg "Konfigurasi user berhasil dikumpulkan"
}

# Function to create config.conf from user input
create_config_file() {
    info_msg "Membuat file config.conf..."
    
    local config_dir="/etc/soc-config"
    run_command "mkdir -p '$config_dir'" "Creating SOC config directory"
    
    cat > "$config_dir/config.conf" << EOF
# =================================================================
# SOC INCIDENT RESPONSE CONFIGURATION - NIST 800-61r2 FRAMEWORK
# =================================================================
# File konfigurasi terpusat untuk semua script IRLC
# Sesuai dengan NIST 800-61r2: Preparation, Detection & Analysis, 
# Containment, Eradication, Recovery, dan Post-Incident Activity

# =================================================================
# PREPARATION PHASE - Konfigurasi Dasar Sistem
# =================================================================

# Direktori web yang akan diproteksi
WEB_DIR="$WEB_DIR"

# Direktori backup utama
BACKUP_DIR="$BACKUP_DIR"

# Direktori karantina untuk file mencurigakan
QUARANTINE_DIR="$QUARANTINE_DIR"

# Direktori log untuk semua aktivitas IRLC
LOG_DIR="$LOG_DIR"

# Direktori konfigurasi SOC
SOC_CONFIG_DIR="$config_dir"

# =================================================================
# DETECTION & ANALYSIS PHASE - Wazuh Integration
# =================================================================

# File alerts.json utama Wazuh
WAZUH_ALERTS_FILE="$WAZUH_ALERTS_FILE"

# Direktori log Wazuh active response
WAZUH_ACTIVE_RESPONSE_LOG_DIR="/var/log/wazuh/active-response"

# Rule IDs untuk deteksi defacement
DEFACE_RULE_IDS="$DEFACE_RULE_IDS"

# Rule IDs untuk deteksi serangan
ATTACK_RULE_IDS="$ATTACK_RULE_IDS"

# Rule IDs untuk trigger eradication
ERADICATION_RULE_IDS="$ERADICATION_RULE_IDS"

# Rule IDs untuk trigger auto restore
RESTORE_RULE_IDS="$RESTORE_RULE_IDS"

# =================================================================
# CONTAINMENT PHASE - Network & System Isolation
# =================================================================

# File untuk mencatat IP yang diblokir
BLOCKED_IPS_FILE="$LOG_DIR/blocked_ips.txt"

# File halaman maintenance
MAINTENANCE_PAGE_FILENAME="maintenance.html"

# File index utama
INDEX_FILENAME="index.html"

# =================================================================
# ERADICATION PHASE - Threat Removal
# =================================================================

# Direktori YARA rules
YARA_RULES_DIR="/var/ossec/etc/rules/yara"

# Socket path ClamAV daemon
CLAMD_SOCKET="/var/run/clamav/clamd.ctl"

# Pattern mencurigakan untuk deteksi (pisahkan dengan |||)
ERADICATION_SUSPICIOUS_PATTERNS="(?i)(eval\s*\(base64_decode\s*\()|||(?i)(passthru\s*\()|||(?i)(shell_exec\s*\()|||(?i)(system\s*\()|||(?i)(exec\s*\()|||(?i)(preg_replace\s*\(.*\/e\s*\))|||(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)|||(?i)(document\.write\s*\(\s*unescape\s*\()|||(?i)(<iframe\s*src\s*=\s*[\"']javascript:)|||(?i)(fsockopen|pfsockopen)\s*\("

# =================================================================
# RECOVERY PHASE - System Restoration
# =================================================================

# Password untuk restore (base64 encoded)
PASSWORD="$ENCODED_PASSWORD"

# Konfigurasi monitoring server
MONITOR_IP="$MONITORING_SERVER"
MONITOR_USER="$MONITORING_USER"
MONITORING_SERVER="$MONITORING_SERVER"
MONITORING_USER="$MONITORING_USER"
MONITORING_PASSWORD="$MONITORING_PASSWORD"

# Path backup remote
REMOTE_GIT_BACKUP_PATH="/home/soc-backup/git-backup"
REMOTE_BACKUP_PATH="$REMOTE_BACKUP_PATH"
REMOTE_DYNAMIC_BACKUP_PATH="/home/soc-backup/dynamic-backup"

# File identitas SSH
SSH_IDENTITY_FILE="/home/soc-backup/.ssh/id_rsa"

# Cache direktori untuk restore dinamis
LOCAL_DYNAMIC_RESTORE_CACHE_DIR="/tmp/soc-dynamic-restore-cache"

# Backup dinamis aktif (true/false)
BACKUP_DYNAMIC="true"

# Direktori dinamis yang akan di-backup (array bash format)
DYNAMIC_DIRS=("uploads" "cache" "temp" "logs")

# User dan group web server
WEB_SERVER_USER="$WEB_SERVER_USER"
WEB_SERVER_GROUP="$WEB_SERVER_GROUP"

# =================================================================
# POST-INCIDENT ACTIVITY - Documentation & Analysis
# =================================================================

# Konfigurasi MISP untuk threat intelligence
MISP_URL="$MISP_URL"
MISP_KEY="$MISP_KEY"
MISP_VERIFY_CERT="$MISP_VERIFY_CERT"

# Direktori untuk laporan insiden
INCIDENT_REPORTS_DIR="$LOG_DIR/reports"

# File audit log
AUDIT_LOG="$LOG_DIR/audit.log"

# File log untuk MISP integration
MISP_LOG_FILE="$LOG_DIR/misp.log"

# =================================================================
# OUTPUT FILES - File Output untuk Setiap Fase
# =================================================================

# File output untuk deteksi IoC
DETECTION_OUTPUT_FILE="/tmp/active_response_500550.log"
DETECTION_LOG_FILE="/tmp/find_last_500550_debug.log"
IOC_DATA_FILE="/tmp/detected_ioc_data.json"

# File output untuk containment
CONTAINMENT_LOG_FILE="/var/log/wazuh/active-response/containment.log"

# File output untuk eradication
ERADICATION_LOG_FILE="/var/log/wazuh/active-response/eradication.log"

# File output untuk restore
RESTORE_LOG_FILE="/var/log/wazuh/active-response/restore.log"
RESTORE_AUTO_LOG_FILE="/var/log/wazuh/active-response/restore_auto.log"

# =================================================================
# SYSTEM INTEGRATION - Integrasi dengan Sistem
# =================================================================

# Timeout untuk operasi (dalam detik)
COMMAND_TIMEOUT="300"
RESTORE_TIMEOUT="600"

# Retry attempts untuk operasi yang gagal
MAX_RETRY_ATTEMPTS="3"

# Interval retry (dalam detik)
RETRY_INTERVAL="30"

# =================================================================
# SECURITY SETTINGS - Pengaturan Keamanan
# =================================================================

# Mode debug (true/false)
DEBUG_MODE="false"

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL="INFO"

# Enkripsi backup (true/false)
ENCRYPT_BACKUP="false"

# Backup retention days
BACKUP_RETENTION_DAYS="30"
EOF

    # Set permissions
    run_command "chmod 600 '$config_dir/config.conf'" "Setting config file permissions"
    run_command "chown root:root '$config_dir/config.conf'" "Setting config file ownership"
    
    # Create symbolic link for backward compatibility
    run_command "mkdir -p '/etc/web-backup'" "Creating web-backup config directory"
    run_command "ln -sf '$config_dir/config.conf' '/etc/web-backup/config.conf'" "Creating symbolic link for backward compatibility"
    
    success_msg "File config.conf berhasil dibuat di $config_dir/config.conf"
}

# ==============================================================================
# FUNGSI INSTALASI WAZUH
# ==============================================================================

# Fungsi untuk mendapatkan interface utama
get_main_interface() {
    # Mendapatkan interface default yang terhubung ke internet
    local main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$main_interface" ]; then
        # Fallback: mengambil interface pertama yang aktif (bukan lo)
        main_interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi
    echo "$main_interface"
}

# Fungsi untuk mendapatkan gateway
get_default_gateway() {
    local gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# Fungsi untuk mendapatkan IP yang tersedia
get_available_ip() {
    local interface=$1
    local gateway=$2
    
    # Mendapatkan network prefix dari gateway
    local network_prefix=$(echo "$gateway" | cut -d. -f1-3)
    
    # Mencoba beberapa IP dalam range yang sama dengan gateway
    for i in {10..20}; do
        local test_ip="${network_prefix}.$i"
        if ! ping -c1 -W1 "$test_ip" &>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # Fallback ke IP default jika tidak ada yang tersedia
    echo "${network_prefix}.10"
}

# Fungsi untuk konfigurasi IP Statis
configure_static_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    local gateway=$4
    local dns1=$5
    local dns2=$6

    info_msg "Menerapkan konfigurasi IP statis: $ip pada interface $interface"

    # Buat direktori netplan jika belum ada
    mkdir -p /etc/netplan

    # Backup file konfigurasi network yang ada
    if [ -f "/etc/netplan/00-installer-config.yaml" ]; then
        cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.backup
    fi

    # Buat konfigurasi netplan baru dengan format yang benar
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${interface}:
      dhcp4: false
      addresses:
        - ${ip}/${netmask}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns1}, ${dns2}]
EOF

    # Set permission yang benar
    chown root:root /etc/netplan/00-installer-config.yaml
    chmod 0600 /etc/netplan/00-installer-config.yaml

    # Generate dan terapkan konfigurasi
    netplan generate

    # Terapkan konfigurasi dengan penanganan error
    if ! netplan apply; then
        warning_msg "Mencoba menerapkan konfigurasi dalam mode debug..."
        netplan --debug apply
    fi

    # Tunggu sebentar untuk interface up
    sleep 5

    # Verifikasi koneksi
    if ping -c 1 ${gateway} > /dev/null 2>&1; then
        success_msg "Konfigurasi IP statis berhasil diterapkan"
        return 0
    else
        error_exit "Gagal menerapkan konfigurasi IP statis"
        if [ -f "/etc/netplan/00-installer-config.yaml.backup" ]; then
            mv /etc/netplan/00-installer-config.yaml.backup /etc/netplan/00-installer-config.yaml
            chmod 0600 /etc/netplan/00-installer-config.yaml
            netplan apply
        fi
        return 1
    fi
}

# Fungsi untuk memeriksa persyaratan sistem Wazuh
check_wazuh_system_requirements() {
    info_msg "Memeriksa persyaratan sistem untuk Wazuh..."
    
    # Periksa RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 4096 ]; then
        warning_msg "RAM kurang dari 4GB. Wazuh membutuhkan minimal 4GB RAM"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Periksa disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        warning_msg "Ruang disk kurang dari 20GB. Wazuh membutuhkan minimal 20GB free space"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Fungsi untuk menangani error Wazuh
handle_wazuh_error() {
    local error_msg="$1"
    error_exit "Wazuh Error: $error_msg"
}

# Fungsi untuk generate perintah instalasi agent Wazuh
generate_wazuh_agent_command() {
    local server_ip=$1
    local WAZUH_VERSION="4.7.5"
    local ARCHITECTURE="amd64"

    info_msg "Membuat generator perintah instalasi Wazuh Agent"
    echo "IP Server Wazuh: $server_ip"

    # Input nama agent
    echo "Masukkan nomor atau nama untuk agent (default: ubuntu-agent):"
    read agent_name
    if [ -z "$agent_name" ]; then
        agent_name="ubuntu-agent"
    fi

    # Generate perintah instalasi
    local install_command="wget https://packages.wazuh.com/${WAZUH_VERSION%.*}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb && sudo WAZUH_MANAGER='${server_ip}' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='${agent_name}' dpkg -i ./wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb"

    # Simpan perintah ke file
    cat > /root/install_wazuh_agent.sh << EOF
#!/bin/bash

# Script instalasi Wazuh Agent
# Generated pada: $(date)
# Server: $server_ip
# Agent Name: $agent_name

$install_command

# Start Wazuh Agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Check status
sudo systemctl status wazuh-agent
EOF

    chmod +x /root/install_wazuh_agent.sh

    success_msg "Script instalasi agent telah dibuat: /root/install_wazuh_agent.sh"
    echo "Perintah instalasi untuk agent:"
    echo "$install_command"
    echo "Atau gunakan script yang telah dibuat:"
    echo "scp /root/install_wazuh_agent.sh user@agent-ip:~/"
    echo "ssh user@agent-ip 'sudo bash ~/install_wazuh_agent.sh'"

    # Tampilkan ringkasan
    echo "Ringkasan Agent Installation:"
    echo "1. Server IP: $server_ip"
    echo "2. Agent Name: $agent_name"
    echo "3. Wazuh Version: $WAZUH_VERSION"
    echo "4. Architecture: $ARCHITECTURE"
    echo "5. Agent Group: default"
}

# Fungsi untuk instalasi Wazuh
install_wazuh() {
    info_msg "Memulai instalasi Wazuh..."
    
    # Deteksi otomatis konfigurasi jaringan
    info_msg "Mendeteksi konfigurasi jaringan..."

    # Deteksi interface utama
    INTERFACE=$(get_main_interface)
    success_msg "Interface terdeteksi: $INTERFACE"

    # Deteksi gateway
    GATEWAY=$(get_default_gateway)
    if [ -z "$GATEWAY" ]; then
        warning_msg "Tidak dapat mendeteksi gateway. Menggunakan default gateway"
        GATEWAY="192.168.1.1"
    fi
    success_msg "Gateway terdeteksi: $GATEWAY"

    # Set IP statis yang tersedia
    STATIC_IP=$(get_available_ip "$INTERFACE" "$GATEWAY")
    success_msg "IP statis yang akan digunakan: $STATIC_IP"

    # Set konfigurasi default
    NETMASK="24"
    DNS1="8.8.8.8"
    DNS2="8.8.4.4"

    # Periksa persyaratan sistem
    check_wazuh_system_requirements

    # Terapkan konfigurasi IP statis
    info_msg "Menerapkan konfigurasi IP statis..."
    configure_static_ip "$STATIC_IP" "$INTERFACE" "$NETMASK" "$GATEWAY" "$DNS1" "$DNS2"

    # Buat direktori untuk menyimpan file instalasi
    INSTALL_DIR="/root/wazuh-install-files"
    mkdir -p ${INSTALL_DIR}
    cd ${INSTALL_DIR}

    # Download Wazuh installer
    info_msg "Mengunduh Wazuh installer..."
    if ! curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh; then
        handle_wazuh_error "Gagal mengunduh installer Wazuh"
    fi

    chmod +x wazuh-install.sh

    # Membuat config.yml
    cat > config.yml << EOF
nodes:
  indexer:
    - name: node-1
      ip: ${STATIC_IP}
      role: master
  server:
    - name: wazuh-1
      ip: ${STATIC_IP}
  dashboard:
    - name: dashboard
      ip: ${STATIC_IP}
EOF

    # Buat direktori untuk menyimpan kredensial
    CRED_DIR="/root/wazuh-credentials"
    mkdir -p ${CRED_DIR}
    chmod 700 ${CRED_DIR}

    # Menjalankan instalasi dengan penanganan error
    success_msg "Memulai instalasi Wazuh..."

    # Generate config files
    if ! ./wazuh-install.sh --generate-config-files; then
        handle_wazuh_error "Gagal generate config files"
    fi
    success_msg "Konfigurasi berhasil di-generate"

    # Install dan start Wazuh indexer
    if ! ./wazuh-install.sh --wazuh-indexer node-1; then
        handle_wazuh_error "Gagal instalasi wazuh indexer"
    fi
    success_msg "Wazuh indexer berhasil diinstal"

    # Tunggu indexer siap
    info_msg "Menunggu Wazuh indexer siap..."
    sleep 30

    # Start cluster
    if ! ./wazuh-install.sh --start-cluster; then
        handle_wazuh_error "Gagal memulai cluster"
    fi
    success_msg "Cluster berhasil dimulai"

    # Simpan password
    info_msg "Menyimpan kredensial..."
    tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > ${CRED_DIR}/wazuh-passwords-full.txt
    chmod 600 ${CRED_DIR}/wazuh-passwords-full.txt

    # Install Wazuh server
    if ! ./wazuh-install.sh --wazuh-server wazuh-1; then
        handle_wazuh_error "Gagal instalasi wazuh server"
    fi
    success_msg "Wazuh server berhasil diinstal"

    # Tunggu server siap
    info_msg "Menunggu Wazuh server siap..."
    sleep 30

    # Install Wazuh dashboard
    if ! ./wazuh-install.sh --wazuh-dashboard dashboard; then
        handle_wazuh_error "Gagal instalasi wazuh dashboard"
    fi
    success_msg "Wazuh dashboard berhasil diinstal"

    # Ekstrak dan simpan password spesifik
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "admin" > ${CRED_DIR}/admin-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "wazuh" > ${CRED_DIR}/wazuh-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "kibana" > ${CRED_DIR}/kibana-passwords.txt

    # Buat file rangkuman kredensial
    cat > ${CRED_DIR}/credentials-summary.txt << EOF
Wazuh Credentials Summary
========================
Tanggal Instalasi: $(date)
IP Server: ${STATIC_IP}

Lokasi File Kredensial:
- Password Lengkap: ${CRED_DIR}/wazuh-passwords-full.txt
- Password Admin: ${CRED_DIR}/admin-passwords.txt
- Password Wazuh: ${CRED_DIR}/wazuh-passwords.txt
- Password Kibana: ${CRED_DIR}/kibana-passwords.txt

Akses Dashboard: https://${STATIC_IP}
Default username: admin

Note: 
- Simpan file ini di tempat yang aman
- Ganti password default setelah login pertama
- Backup folder ${CRED_DIR} secara berkala
EOF

    # Set permission untuk file kredensial
    chmod 600 ${CRED_DIR}/*
    chown -R root:root ${CRED_DIR}

    # Tambahkan entri ke /etc/hosts
    echo "${STATIC_IP} node-1 wazuh-1 dashboard" >> /etc/hosts

    # Periksa status layanan
    info_msg "Memeriksa status layanan..."
    services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            success_msg "Service $service berjalan dengan baik"
        else
            warning_msg "Service $service tidak berjalan"
            systemctl status $service
            info_msg "Mencoba restart service ${service}..."
            systemctl restart $service
            sleep 5
            if systemctl is-active --quiet $service; then
                success_msg "Service $service berhasil direstart"
            else
                warning_msg "Service $service masih bermasalah"
            fi
        fi
    done

    # Simpan informasi konfigurasi
    cat > /root/wazuh-info.txt << EOF
Konfigurasi Wazuh:
=================
IP Address: ${STATIC_IP}
Interface: ${INTERFACE}
Netmask: ${NETMASK}
Gateway: ${GATEWAY}
DNS1: ${DNS1}
DNS2: ${DNS2}

Dashboard URL: https://${STATIC_IP}

Lokasi File Kredensial: ${CRED_DIR}
EOF

    success_msg "Instalasi Wazuh selesai!"
    echo "Anda dapat mengakses dashboard di: https://${STATIC_IP}"
    echo "Kredensial tersimpan di: ${CRED_DIR}"
    echo "Informasi konfigurasi tersimpan di: /root/wazuh-info.txt"

    # Generate script instalasi agent
    info_msg "Membuat script instalasi untuk Wazuh Agent..."
    generate_wazuh_agent_command "${STATIC_IP}"

    success_msg "Proses instalasi dan konfigurasi Wazuh selesai!"
    
    # Return ke direktori asal
    cd "$SCRIPT_DIR"
}

# ==============================================================================
# FUNGSI INSTALASI MISP
# ==============================================================================

# Function to check MISP dependencies
check_misp_dependencies() {
    info_msg "Checking MISP dependencies..."
    if ! command -v docker &> /dev/null; then
        error_exit "Error: 'docker' is not installed. Please install Docker first."
    fi
    if ! command -v docker-compose &> /dev/null; then
        error_exit "Error: 'docker-compose' is not installed. Please install Docker Compose first."
    fi
    success_msg "MISP dependencies are satisfied."
}

# Function to wait for MISP to become available
wait_for_misp() {
    info_msg "Waiting for MISP to become available... This may take several minutes."
    until curl --output /dev/null --silent --head --fail --insecure https://localhost; do
        printf '.'
        sleep 5
    done
    success_msg "MISP is up and running!"
}

# Function to install and setup MISP
install_misp() {
    info_msg "Memulai instalasi MISP..."
    
    # MISP Configuration
    MISP_INSTALL_DIR="/opt/misp-docker"
    MISP_DOCKER_COMPOSE_URL="https://raw.githubusercontent.com/misp/misp-docker/main/docker-compose.yml"
    
    # Detail untuk pengguna API yang akan dibuat
    ORG_NAME="Wazuh-IR-Automation"
    USER_EMAIL_FOR_KEY="wazuh-automation@localhost.local"
    USER_COMMENT="API key for Wazuh Active Response integration"
    
    check_misp_dependencies
    
    # Periksa apakah kontainer MISP sudah berjalan
    MISP_CONTAINER_ID=$(docker ps -q --filter "name=misp-server")
    
    if [ -z "$MISP_CONTAINER_ID" ]; then
        info_msg "MISP container not found. Starting installation process..."
        
        # 1. Buat direktori instalasi
        info_msg "Creating installation directory at ${MISP_INSTALL_DIR}..."
        run_command "mkdir -p '$MISP_INSTALL_DIR'" "Creating MISP installation directory"
        cd "$MISP_INSTALL_DIR"
        
        # 2. Unduh file docker-compose.yml
        info_msg "Downloading latest misp-docker docker-compose.yml..."
        run_command "curl -o docker-compose.yml '$MISP_DOCKER_COMPOSE_URL'" "Downloading MISP docker-compose file"
        
        # 3. Jalankan MISP menggunakan docker-compose
        info_msg "Starting MISP containers in detached mode (-d)..."
        run_command "docker-compose up -d" "Starting MISP containers"
        
        # 4. Tunggu hingga MISP benar-benar siap
        wait_for_misp
        
        success_msg "MISP installation completed successfully."
    else
        success_msg "MISP is already installed and running."
        # Pastikan kita berada di direktori yang benar untuk perintah exec
        cd "$MISP_INSTALL_DIR"
    fi
    
    # Pengambilan API Key
    info_msg "Attempting to create/retrieve API key for user '${USER_EMAIL_FOR_KEY}'..."
    
    # Dapatkan email admin default dari dalam kontainer
    ADMIN_EMAIL=$(docker-compose exec -T misp-server cat /var/www/MISP/app/Config/config.php | grep "'email' =>" | head -1 | sed "s/.*'email' => '\([^']*\)'.*/\1/")
    
    if [ -z "$ADMIN_EMAIL" ]; then
        warning_msg "Could not automatically determine admin email. Defaulting to 'admin@admin.test'."
        ADMIN_EMAIL="admin@admin.test"
    fi
    
    info_msg "Using admin email: ${ADMIN_EMAIL}"
    
    # Gunakan perintah 'cake' di dalam kontainer untuk membuat pengguna dan mendapatkan kuncinya
    API_KEY_OUTPUT=$(docker-compose exec -T misp-server \
        /var/www/MISP/app/Console/cake Admin setApiUser "$ADMIN_EMAIL" "$ORG_NAME" "$USER_EMAIL_FOR_KEY" "$USER_COMMENT")
    
    # Ekstrak kunci API dari output
    MISP_KEY=$(echo "$API_KEY_OUTPUT" | grep 'Auth key:' | awk '{print $3}')
    
    if [ -n "$MISP_KEY" ]; then
        success_msg "Successfully retrieved API Key!"
        echo "------------------------------------------------------------------"
        echo "Your MISP API Key is: $MISP_KEY"
        echo "------------------------------------------------------------------"
        echo "Simpan kunci ini di tempat yang aman. Anda akan membutuhkannya untuk"
        echo "mengkonfigurasi skrip integrasi Wazuh."
        
        # Update config.conf dengan API key yang baru
        if [ -f "/etc/soc-config/config.conf" ]; then
            sed -i "s/MISP_KEY=.*/MISP_KEY=\"$MISP_KEY\"/" /etc/soc-config/config.conf
            success_msg "MISP API Key berhasil diupdate di config.conf"
        fi
    else
        error_exit "Error: Failed to retrieve API Key."
        info_msg "Please check the logs using 'docker-compose logs -f' in '${MISP_INSTALL_DIR}'."
    fi
    
    success_msg "MISP setup completed successfully!"
}

# ==============================================================================
# FUNGSI INSTALASI SERVER MONITORING
# ==============================================================================

# Function to setup monitoring server (backup repository)
install_monitoring_server() {
    info_msg "Memulai instalasi Server Monitoring (Backup Repository)..."
    
    # Tentukan direktori untuk menyimpan backup
    info_msg "Menentukan direktori untuk menyimpan backup Git dan arsip dinamis..."
    read -r -p "Masukkan path direktori utama backup (default: /var/backup/web_backups): " MAIN_BACKUP_DIR
    MAIN_BACKUP_DIR=${MAIN_BACKUP_DIR:-/var/backup/web_backups}

    # Path untuk backup Git (repositori bare)
    GIT_BACKUP_SUBDIR="git_repo" # Nama subdirektori untuk Git
    ACTUAL_GIT_BACKUP_PATH="$MAIN_BACKUP_DIR/$GIT_BACKUP_SUBDIR"

    # Path untuk backup file dinamis (arsip .tar.gz)
    DYNAMIC_BACKUP_SUBDIR="dynamic_archives" # Nama subdirektori untuk arsip dinamis
    ACTUAL_DYNAMIC_BACKUP_PATH="$MAIN_BACKUP_DIR/$DYNAMIC_BACKUP_SUBDIR"

    # Buat direktori backup jika belum ada
    if [ ! -d "$ACTUAL_GIT_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup Git: $ACTUAL_GIT_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_GIT_BACKUP_PATH'" "Creating Git backup directory"
    fi
    if [ ! -d "$ACTUAL_DYNAMIC_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup dinamis: $ACTUAL_DYNAMIC_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_DYNAMIC_BACKUP_PATH'" "Creating dynamic backup directory"
    fi

    # Membuat pengguna khusus untuk backup
    echo ""
    info_msg "Pengaturan Pengguna Khusus untuk Menerima Backup"
    echo "----------------------------------------------------"
    read -r -p "Apakah Anda ingin membuat pengguna sistem khusus untuk menerima backup via SSH? (y/n, default: y): " CREATE_USER
    CREATE_USER=${CREATE_USER:-y}

    BACKUP_USER="" # Akan diisi jika CREATE_USER=y

    if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]]; then
        read -r -p "Masukkan nama pengguna untuk backup (default: webbackupuser): " INPUT_BACKUP_USER
        BACKUP_USER=${INPUT_BACKUP_USER:-webbackupuser}
        
        if id "$BACKUP_USER" &>/dev/null; then
            info_msg "Pengguna '$BACKUP_USER' sudah ada."
        else
            info_msg "Membuat pengguna '$BACKUP_USER'..."
            run_command "useradd -r -m -s /bin/bash '$BACKUP_USER'" "Creating backup user"
            success_msg "Pengguna '$BACKUP_USER' berhasil dibuat."
        fi
        
        info_msg "Mengatur kepemilikan direktori backup untuk pengguna '$BACKUP_USER'..."
        run_command "chown -R '$BACKUP_USER:$BACKUP_USER' '$MAIN_BACKUP_DIR'" "Setting ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting permissions of backup directory"

        # Inisialisasi repository Git bare
        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH'..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
            read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        
        # Mengatur SSH untuk pengguna backup
        USER_SSH_DIR="/home/$BACKUP_USER/.ssh"
        info_msg "Memastikan direktori SSH '$USER_SSH_DIR' dan 'authorized_keys' ada untuk pengguna '$BACKUP_USER'..."
        run_command "sudo -u '$BACKUP_USER' mkdir -p '$USER_SSH_DIR'" "Creating SSH directory for backup user"
        run_command "sudo -u '$BACKUP_USER' touch '$USER_SSH_DIR/authorized_keys'" "Creating authorized_keys file"
        run_command "sudo -u '$BACKUP_USER' chmod 700 '$USER_SSH_DIR'" "Setting SSH directory permissions"
        run_command "sudo -u '$BACKUP_USER' chmod 600 '$USER_SSH_DIR/authorized_keys'" "Setting authorized_keys permissions"
        success_msg "Setup direktori SSH untuk '$BACKUP_USER' selesai."
        
        echo ""
        info_msg "--- INSTRUKSI PENTING UNTUK SERVER WEB ---"
        echo "Untuk mengizinkan server web melakukan push backup ke server monitoring ini:"
        echo "1. Di SERVER WEB, pastikan Anda memiliki SSH key pair untuk user root (atau user yang menjalankan backup)."
        echo "   Kunci publiknya (biasanya di '/root/.ssh/id_rsa_web_backup.pub') perlu disalin."
        echo "2. Di SERVER MONITORING INI, tambahkan isi kunci publik tersebut ke dalam file:"
        echo "   $USER_SSH_DIR/authorized_keys"
        echo "3. Pastikan pengguna '$BACKUP_USER' adalah pemilik file tersebut dan memiliki izin yang benar (chmod 600)."
        echo "--------------------------------------------"

    else # Jika tidak membuat pengguna khusus, backup akan diterima oleh root
        BACKUP_USER="root" # Backup akan menggunakan root jika tidak ada user khusus
        warning_msg "PERINGATAN: Tidak ada pengguna khusus yang dibuat. Backup akan diterima sebagai pengguna 'root'. Ini kurang aman."
        info_msg "Pastikan direktori '$MAIN_BACKUP_DIR' dapat ditulis oleh root."
        run_command "chown -R 'root:root' '$MAIN_BACKUP_DIR'" "Setting root ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting root permissions of backup directory"

        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH' sebagai root..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
             read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository as root"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository as root"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        info_msg "SSH key dari server web perlu ditambahkan ke '/root/.ssh/authorized_keys' di server monitoring ini."
    fi

    # Konfigurasi Monitoring Server Ini Sendiri (Opsional)
    echo ""
    info_msg "Konfigurasi Monitoring untuk Server Backup Ini Sendiri (Opsional)"
    echo "-------------------------------------------------------------------"
    read -r -p "Apakah Anda ingin menginstal Wazuh Agent untuk memonitor server backup ini sendiri? (y/n, default: n): " INSTALL_WAZUH_AGENT_LOCAL
    INSTALL_WAZUH_AGENT_LOCAL=${INSTALL_WAZUH_AGENT_LOCAL:-n}

    if [[ "$INSTALL_WAZUH_AGENT_LOCAL" == "y" || "$INSTALL_WAZUH_AGENT_LOCAL" == "Y" ]]; then
        info_msg "Memulai instalasi Wazuh Agent untuk server backup ini..."
        
        if ! command -v apt-key &> /dev/null || ! command -v tee &> /dev/null ; then
            run_command "apt-get install -y gnupg apt-transport-https" "Installing gnupg and apt-transport-https"
        fi

        run_command "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg" "Importing Wazuh GPG key"
        run_command "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list" "Adding Wazuh repository"
        
        run_command "apt-get update -y" "Updating package list after adding Wazuh repository"
        run_command "apt-get install -y wazuh-agent" "Installing Wazuh Agent"
        
        read -r -p "Masukkan alamat IP Wazuh Manager untuk agent ini: " WAZUH_MANAGER_IP_FOR_AGENT
        while [[ -z "$WAZUH_MANAGER_IP_FOR_AGENT" ]]; do
            read -r -p "Alamat IP Wazuh Manager tidak boleh kosong. Masukkan IP: " WAZUH_MANAGER_IP_FOR_AGENT
        done
        
        # Konfigurasi Wazuh Agent (ossec.conf)
        run_command "sed -i 's|<address>MANAGER_IP</address>|<address>$WAZUH_MANAGER_IP_FOR_AGENT</address>|g' /var/ossec/etc/ossec.conf" "Configuring Wazuh Agent manager IP"
        
        run_command "systemctl daemon-reload" "Reloading systemd daemon"
        run_command "systemctl enable wazuh-agent" "Enabling Wazuh Agent service"
        run_command "systemctl restart wazuh-agent" "Starting Wazuh Agent service"
        
        success_msg "Wazuh Agent berhasil diinstal dan dikonfigurasi untuk memonitor server backup ini."
        info_msg "Pastikan untuk mendaftarkan agent ini di Wazuh Manager."
    else
        info_msg "Instalasi Wazuh Agent untuk server backup ini dilewati."
    fi

    # Konfigurasi Git Hooks untuk Notifikasi (opsional)
    echo ""
    info_msg "Konfigurasi Git Hook untuk Notifikasi Email (Opsional)"
    echo "---------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur notifikasi email setiap kali backup Git diterima? (y/n, default: n): " SETUP_NOTIFICATION
    SETUP_NOTIFICATION=${SETUP_NOTIFICATION:-n}

    if [[ "$SETUP_NOTIFICATION" == "y" || "$SETUP_NOTIFICATION" == "Y" ]]; then
        if ! command -v mail &> /dev/null; then
            info_msg "Command 'mail' (mailutils) tidak ditemukan. Menginstal..."
            run_command "apt-get install -y mailutils" "Installing mailutils for email notifications"
        fi

        if command -v mail &> /dev/null; then
            read -r -p "Masukkan alamat email untuk notifikasi: " NOTIFY_EMAIL
            while [[ -z "$NOTIFY_EMAIL" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " NOTIFY_EMAIL
            done
            
            HOOK_DIR="$ACTUAL_GIT_BACKUP_PATH/hooks"
            HOOK_FILE="$HOOK_DIR/post-receive"

            info_msg "Membuat direktori hook $HOOK_DIR jika belum ada..."
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "sudo -u '$BACKUP_USER' mkdir -p '$HOOK_DIR'" "Creating hook directory as backup user"
            else
                run_command "mkdir -p '$HOOK_DIR'" "Creating hook directory"
            fi

            info_msg "Membuat skrip post-receive hook di $HOOK_FILE..."
            cat > "$HOOK_FILE" << EOF_HOOK
#!/bin/bash
# Git hook untuk mengirim notifikasi email saat menerima backup baru

REPO_NAME="\$(basename "\$(pwd)")"
COMMIT_INFO=\$(git log -1 --pretty=format:"%h - %an, %ar : %s")
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=\$(date +"%Y-%m-%d %H:%M:%S")

mail -s "Backup GIT Baru Diterima di \$SERVER_HOSTNAME untuk \$REPO_NAME" "$NOTIFY_EMAIL" << EOM_MAIL
Backup Git baru telah diterima di server monitoring: \$SERVER_HOSTNAME

Repository Path: \$(pwd)
Timestamp: \$TIMESTAMP
Commit Terakhir: \$COMMIT_INFO

Pesan ini dikirim otomatis dari hook post-receive.
EOM_MAIL
EOF_HOOK

            run_command "chmod +x '$HOOK_FILE'" "Making hook file executable"
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "chown '$BACKUP_USER:$BACKUP_USER' '$HOOK_FILE'" "Setting hook file ownership to backup user"
                info_msg "Kepemilikan hook diatur ke $BACKUP_USER."
            fi
            success_msg "Notifikasi email untuk backup Git baru telah dikonfigurasi di $HOOK_FILE."
            info_msg "Pastikan MTA (seperti Postfix atau ssmtp) terkonfigurasi di server ini agar perintah 'mail' berfungsi."
        else
            warning_msg "Gagal menginstal atau menemukan 'mail'. Notifikasi email dilewati."
        fi
    fi

    # Monitoring disk space untuk MAIN_BACKUP_DIR (opsional)
    echo ""
    info_msg "Monitoring Disk Space untuk Direktori Backup (Opsional)"
    echo "-----------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur monitoring disk space untuk '$MAIN_BACKUP_DIR'? (y/n, default: y): " SETUP_DISK_MONITORING
    SETUP_DISK_MONITORING=${SETUP_DISK_MONITORING:-y}

    if [[ "$SETUP_DISK_MONITORING" == "y" || "$SETUP_DISK_MONITORING" == "Y" ]]; then
        if ! command -v mail &> /dev/null && ! command -v mailx &> /dev/null ; then
            info_msg "Command 'mail' atau 'mailx' tidak ditemukan. Menginstal mailutils..."
            run_command "apt-get install -y mailutils" "Installing mailutils for disk monitoring"
        fi

        if command -v mail &> /dev/null || command -v mailx &> /dev/null ; then
            MONITOR_SCRIPT_PATH="/usr/local/bin/monitor_backup_disk_space.sh"
            info_msg "Membuat skrip monitoring disk di $MONITOR_SCRIPT_PATH..."

            cat > "$MONITOR_SCRIPT_PATH" << EOF_DISK_MON
#!/bin/bash
# Skrip untuk memonitor penggunaan disk direktori backup

TARGET_BACKUP_DIR="\$1"
USAGE_THRESHOLD="\$2" # Persentase, misal 80
EMAIL_RECIPIENT="\$3"
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
LOG_FILE="/var/log/backup_disk_monitor.log"
MAIL_COMMAND=\$(command -v mail || command -v mailx)

if [ -z "\$MAIL_COMMAND" ]; then
    echo "[\$(date)] Error: Perintah mail/mailx tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

if [ ! -d "\$TARGET_BACKUP_DIR" ]; then
    echo "[\$(date)] Error: Direktori backup '\$TARGET_BACKUP_DIR' tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

CURRENT_USAGE=\$(df "\$TARGET_BACKUP_DIR" | awk 'NR==2 {print \$5}' | sed 's/%//')

if [ -z "\$CURRENT_USAGE" ]; then
    echo "[\$(date)] Error: Tidak dapat mengambil info penggunaan disk untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
    exit 1
fi

if [ "\$CURRENT_USAGE" -gt "\$USAGE_THRESHOLD" ]; then
    SUBJECT="[PERINGATAN] Disk Backup di \$SERVER_HOSTNAME Hampir Penuh (\$CURRENT_USAGE%)"
    MESSAGE="Penggunaan disk pada direktori backup '\$TARGET_BACKUP_DIR' di server \$SERVER_HOSTNAME telah mencapai \$CURRENT_USAGE% (Threshold: \$USAGE_THRESHOLD%).\n\nDetail Penggunaan Disk:\n\$(df -h "\$TARGET_BACKUP_DIR")\n\nHarap segera periksa dan kosongkan ruang jika perlu."
    
    echo -e "\$MESSAGE" | \$MAIL_COMMAND -s "\$SUBJECT" "\$EMAIL_RECIPIENT"
    echo "[\$(date)] Peringatan Terkirim: Penggunaan disk \$CURRENT_USAGE% melebihi threshold \$USAGE_THRESHOLD% untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
else
    echo "[\$(date)] Info: Penggunaan disk \$CURRENT_USAGE% untuk '\$TARGET_BACKUP_DIR' masih di bawah threshold \$USAGE_THRESHOLD%." >> "\$LOG_FILE"
fi
exit 0
EOF_DISK_MON
            run_command "chmod +x '$MONITOR_SCRIPT_PATH'" "Making disk monitoring script executable"
            success_msg "Skrip monitoring disk $MONITOR_SCRIPT_PATH berhasil dibuat."

            read -r -p "Masukkan threshold penggunaan disk dalam persen (misal 80, default: 80): " DISK_THRESHOLD_INPUT
            DISK_THRESHOLD_INPUT=${DISK_THRESHOLD_INPUT:-80}
            read -r -p "Masukkan alamat email untuk notifikasi disk space: " DISK_EMAIL_INPUT
            while [[ -z "$DISK_EMAIL_INPUT" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " DISK_EMAIL_INPUT
            done
            
            CRON_DISK_MON_ENTRY="0 7 * * * $MONITOR_SCRIPT_PATH \"$MAIN_BACKUP_DIR\" \"$DISK_THRESHOLD_INPUT\" \"$DISK_EMAIL_INPUT\""
            
            # Tambahkan ke crontab root
            run_command "(crontab -l 2>/dev/null | grep -vF '$MONITOR_SCRIPT_PATH'; echo '$CRON_DISK_MON_ENTRY') | crontab -" "Adding disk monitoring to crontab"
            success_msg "Monitoring disk space untuk direktori backup '$MAIN_BACKUP_DIR' telah diatur via cron."
            info_msg "Log monitoring disk akan ada di /var/log/backup_disk_monitor.log"
        else
            warning_msg "Gagal menginstal atau menemukan 'mail/mailx'. Monitoring disk space dilewati."
        fi
    fi

    SERVER_IP_ADDRESS=$(hostname -I | awk '{print $1}') # Ambil IP utama

    echo ""
    echo "================================================================="
    echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
    echo "================================================================="
    echo ""
    echo "Informasi Penting untuk Konfigurasi Server Web:"
    echo "----------------------------------------------"
    echo "IP Server Monitoring Ini: ${SERVER_IP_ADDRESS:-Mohon periksa manual}"
    echo "Pengguna SSH untuk Backup: $BACKUP_USER"
    echo "Path Tujuan Backup Git: $ACTUAL_GIT_BACKUP_PATH"
    echo "Path Tujuan Backup Dinamis (arsip): $ACTUAL_DYNAMIC_BACKUP_PATH"
    echo ""
    echo "Contoh Perintah di Server Web untuk Menambahkan Remote Git:"
    echo "   git remote add monitoring $BACKUP_USER@${SERVER_IP_ADDRESS:-<IP_SERVER_MONITORING>}:$ACTUAL_GIT_BACKUP_PATH"
    echo ""
    echo "CATATAN PENTING:"
    echo "- Format URL Git SSH yang disarankan: '$BACKUP_USER@<IP_SERVER_MONITORING>:$ACTUAL_GIT_BACKUP_PATH' (gunakan path absolut)."
    echo "- Pastikan kunci SSH publik dari server web (user root atau yang menjalankan backup) telah ditambahkan ke:"
    echo "  '/home/$BACKUP_USER/.ssh/authorized_keys' (jika $BACKUP_USER dibuat) atau '/root/.ssh/authorized_keys' (jika tidak ada user khusus) di server monitoring ini."
    echo "- Pastikan direktori '$ACTUAL_DYNAMIC_BACKUP_PATH' dapat ditulis oleh '$BACKUP_USER' (atau root) melalui rsync/scp."
    echo ""
    echo "Server monitoring ini sekarang siap menerima backup."
    echo "================================================================="
}

# ==============================================================================
# FUNGSI KONFIGURASI SOC
# ==============================================================================

# Function to collect user input for configuration
collect_user_config() {
    info_msg "Mengumpulkan konfigurasi dari user..."
    
    # Web directory
    read -r -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
    WEB_DIR=${WEB_DIR:-/var/www/html}
    
    # Backup directory
    read -r -p "Masukkan path direktori backup (default: /var/soc-backup): " BACKUP_DIR
    BACKUP_DIR=${BACKUP_DIR:-/var/soc-backup}
    
    # Quarantine directory
    read -r -p "Masukkan path direktori karantina (default: /var/soc-quarantine): " QUARANTINE_DIR
    QUARANTINE_DIR=${QUARANTINE_DIR:-/var/soc-quarantine}
    
    # Log directory
    read -r -p "Masukkan path direktori log (default: /var/log/soc-incident-response): " LOG_DIR
    LOG_DIR=${LOG_DIR:-/var/log/soc-incident-response}
    
    # Wazuh alerts file
    read -r -p "Masukkan path file alerts Wazuh (default: /var/ossec/logs/alerts/alerts.json): " WAZUH_ALERTS_FILE
    WAZUH_ALERTS_FILE=${WAZUH_ALERTS_FILE:-/var/ossec/logs/alerts/alerts.json}
    
    # Rule IDs
    read -r -p "Masukkan Rule IDs untuk defacement (default: 550,554,5501,5502,5503,5504,100001,100002): " DEFACE_RULE_IDS
    DEFACE_RULE_IDS=${DEFACE_RULE_IDS:-550,554,5501,5502,5503,5504,100001,100002}
    
    read -r -p "Masukkan Rule IDs untuk serangan (default: 5710,5712,5715,5760,100003,100004): " ATTACK_RULE_IDS
    ATTACK_RULE_IDS=${ATTACK_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk eradication (default: 5710,5712,5715,5760,100003,100004): " ERADICATION_RULE_IDS
    ERADICATION_RULE_IDS=${ERADICATION_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk restore (default: 100010,100011,100012): " RESTORE_RULE_IDS
    RESTORE_RULE_IDS=${RESTORE_RULE_IDS:-100010,100011,100012}
    
    # MISP Configuration
    read -r -p "Masukkan URL MISP (default: https://192.168.28.135): " MISP_URL
    MISP_URL=${MISP_URL:-https://192.168.28.135}
    
    read -r -p "Masukkan API Key MISP: " MISP_KEY
    if [[ -z "$MISP_KEY" ]]; then
        MISP_KEY="XweOnEWOtWFmIbW585H2m03R3SIZRmIKxrza73WB"
        warning_msg "Menggunakan API Key default MISP"
    fi
    
    read -r -p "Verifikasi sertifikat MISP? (y/n, default: n): " MISP_VERIFY_CERT
    if [[ "$MISP_VERIFY_CERT" =~ ^[Yy]$ ]]; then
        MISP_VERIFY_CERT="true"
    else
        MISP_VERIFY_CERT="false"
    fi
    
    # Monitoring server
    while true; do
        read -r -p "Masukkan IP server monitoring (default: 192.168.1.100): " MONITORING_SERVER
        MONITORING_SERVER=${MONITORING_SERVER:-192.168.1.100}
        if validate_ip "$MONITORING_SERVER"; then
            break
        else
            warning_msg "IP address tidak valid. Silakan coba lagi."
        fi
    done
    
    read -r -p "Masukkan username server monitoring (default: soc-backup): " MONITORING_USER
    MONITORING_USER=${MONITORING_USER:-soc-backup}
    
    read -s -p "Masukkan password server monitoring: " MONITORING_PASSWORD
    echo
    
    # Backup paths
    read -r -p "Masukkan path backup remote (default: /home/soc-backup/backups): " REMOTE_BACKUP_PATH
    REMOTE_BACKUP_PATH=${REMOTE_BACKUP_PATH:-/home/soc-backup/backups}
    
    # Web server user/group
    read -r -p "Masukkan user web server (default: www-data): " WEB_SERVER_USER
    WEB_SERVER_USER=${WEB_SERVER_USER:-www-data}
    
    read -r -p "Masukkan group web server (default: www-data): " WEB_SERVER_GROUP
    WEB_SERVER_GROUP=${WEB_SERVER_GROUP:-www-data}
    
    # Password untuk restore
    read -s -p "Masukkan password untuk restore (minimal 12 karakter): " RESTORE_PASSWORD
    echo
    if [[ ${#RESTORE_PASSWORD} -lt 12 ]]; then
        error_exit "Password harus minimal 12 karakter"
    fi
    ENCODED_PASSWORD=$(echo -n "$RESTORE_PASSWORD" | base64)
    
    success_msg "Konfigurasi user berhasil dikumpulkan"
}

# Function to create config.conf from user input
create_config_file() {
    info_msg "Membuat file config.conf..."
    
    local config_dir="/etc/soc-config"
    run_command "mkdir -p '$config_dir'" "Creating SOC config directory"
    
    cat > "$config_dir/config.conf" << EOF
# =================================================================
# SOC INCIDENT RESPONSE CONFIGURATION - NIST 800-61r2 FRAMEWORK
# =================================================================
# File konfigurasi terpusat untuk semua script IRLC
# Sesuai dengan NIST 800-61r2: Preparation, Detection & Analysis, 
# Containment, Eradication, Recovery, dan Post-Incident Activity

# =================================================================
# PREPARATION PHASE - Konfigurasi Dasar Sistem
# =================================================================

# Direktori web yang akan diproteksi
WEB_DIR="$WEB_DIR"

# Direktori backup utama
BACKUP_DIR="$BACKUP_DIR"

# Direktori karantina untuk file mencurigakan
QUARANTINE_DIR="$QUARANTINE_DIR"

# Direktori log untuk semua aktivitas IRLC
LOG_DIR="$LOG_DIR"

# Direktori konfigurasi SOC
SOC_CONFIG_DIR="$config_dir"

# =================================================================
# DETECTION & ANALYSIS PHASE - Wazuh Integration
# =================================================================

# File alerts.json utama Wazuh
WAZUH_ALERTS_FILE="$WAZUH_ALERTS_FILE"

# Direktori log Wazuh active response
WAZUH_ACTIVE_RESPONSE_LOG_DIR="/var/log/wazuh/active-response"

# Rule IDs untuk deteksi defacement
DEFACE_RULE_IDS="$DEFACE_RULE_IDS"

# Rule IDs untuk deteksi serangan
ATTACK_RULE_IDS="$ATTACK_RULE_IDS"

# Rule IDs untuk trigger eradication
ERADICATION_RULE_IDS="$ERADICATION_RULE_IDS"

# Rule IDs untuk trigger auto restore
RESTORE_RULE_IDS="$RESTORE_RULE_IDS"

# =================================================================
# CONTAINMENT PHASE - Network & System Isolation
# =================================================================

# File untuk mencatat IP yang diblokir
BLOCKED_IPS_FILE="$LOG_DIR/blocked_ips.txt"

# File halaman maintenance
MAINTENANCE_PAGE_FILENAME="maintenance.html"

# File index utama
INDEX_FILENAME="index.html"

# =================================================================
# ERADICATION PHASE - Threat Removal
# =================================================================

# Direktori YARA rules
YARA_RULES_DIR="/var/ossec/etc/rules/yara"

# Socket path ClamAV daemon
CLAMD_SOCKET="/var/run/clamav/clamd.ctl"

# Pattern mencurigakan untuk deteksi (pisahkan dengan |||)
ERADICATION_SUSPICIOUS_PATTERNS="(?i)(eval\s*\(base64_decode\s*\()|||(?i)(passthru\s*\()|||(?i)(shell_exec\s*\()|||(?i)(system\s*\()|||(?i)(exec\s*\()|||(?i)(preg_replace\s*\(.*\/e\s*\))|||(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)|||(?i)(document\.write\s*\(\s*unescape\s*\()|||(?i)(<iframe\s*src\s*=\s*[\"']javascript:)|||(?i)(fsockopen|pfsockopen)\s*\("

# =================================================================
# RECOVERY PHASE - System Restoration
# =================================================================

# Password untuk restore (base64 encoded)
PASSWORD="$ENCODED_PASSWORD"

# Konfigurasi monitoring server
MONITOR_IP="$MONITORING_SERVER"
MONITOR_USER="$MONITORING_USER"
MONITORING_SERVER="$MONITORING_SERVER"
MONITORING_USER="$MONITORING_USER"
MONITORING_PASSWORD="$MONITORING_PASSWORD"

# Path backup remote
REMOTE_GIT_BACKUP_PATH="/home/soc-backup/git-backup"
REMOTE_BACKUP_PATH="$REMOTE_BACKUP_PATH"
REMOTE_DYNAMIC_BACKUP_PATH="/home/soc-backup/dynamic-backup"

# File identitas SSH
SSH_IDENTITY_FILE="/home/soc-backup/.ssh/id_rsa"

# Cache direktori untuk restore dinamis
LOCAL_DYNAMIC_RESTORE_CACHE_DIR="/tmp/soc-dynamic-restore-cache"

# Backup dinamis aktif (true/false)
BACKUP_DYNAMIC="true"

# Direktori dinamis yang akan di-backup (array bash format)
DYNAMIC_DIRS=("uploads" "cache" "temp" "logs")

# User dan group web server
WEB_SERVER_USER="$WEB_SERVER_USER"
WEB_SERVER_GROUP="$WEB_SERVER_GROUP"

# =================================================================
# POST-INCIDENT ACTIVITY - Documentation & Analysis
# =================================================================

# Konfigurasi MISP untuk threat intelligence
MISP_URL="$MISP_URL"
MISP_KEY="$MISP_KEY"
MISP_VERIFY_CERT="$MISP_VERIFY_CERT"

# Direktori untuk laporan insiden
INCIDENT_REPORTS_DIR="$LOG_DIR/reports"

# File audit log
AUDIT_LOG="$LOG_DIR/audit.log"

# File log untuk MISP integration
MISP_LOG_FILE="$LOG_DIR/misp.log"

# =================================================================
# OUTPUT FILES - File Output untuk Setiap Fase
# =================================================================

# File output untuk deteksi IoC
DETECTION_OUTPUT_FILE="/tmp/active_response_500550.log"
DETECTION_LOG_FILE="/tmp/find_last_500550_debug.log"
IOC_DATA_FILE="/tmp/detected_ioc_data.json"

# File output untuk containment
CONTAINMENT_LOG_FILE="/var/log/wazuh/active-response/containment.log"

# File output untuk eradication
ERADICATION_LOG_FILE="/var/log/wazuh/active-response/eradication.log"

# File output untuk restore
RESTORE_LOG_FILE="/var/log/wazuh/active-response/restore.log"
RESTORE_AUTO_LOG_FILE="/var/log/wazuh/active-response/restore_auto.log"

# =================================================================
# SYSTEM INTEGRATION - Integrasi dengan Sistem
# =================================================================

# Timeout untuk operasi (dalam detik)
COMMAND_TIMEOUT="300"
RESTORE_TIMEOUT="600"

# Retry attempts untuk operasi yang gagal
MAX_RETRY_ATTEMPTS="3"

# Interval retry (dalam detik)
RETRY_INTERVAL="30"

# =================================================================
# SECURITY SETTINGS - Pengaturan Keamanan
# =================================================================

# Mode debug (true/false)
DEBUG_MODE="false"

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL="INFO"

# Enkripsi backup (true/false)
ENCRYPT_BACKUP="false"

# Backup retention days
BACKUP_RETENTION_DAYS="30"
EOF

    # Set permissions
    run_command "chmod 600 '$config_dir/config.conf'" "Setting config file permissions"
    run_command "chown root:root '$config_dir/config.conf'" "Setting config file ownership"
    
    # Create symbolic link for backward compatibility
    run_command "mkdir -p '/etc/web-backup'" "Creating web-backup config directory"
    run_command "ln -sf '$config_dir/config.conf' '/etc/web-backup/config.conf'" "Creating symbolic link for backward compatibility"
    
    success_msg "File config.conf berhasil dibuat di $config_dir/config.conf"
}

# ==============================================================================
# FUNGSI INSTALASI WAZUH
# ==============================================================================

# Fungsi untuk mendapatkan interface utama
get_main_interface() {
    # Mendapatkan interface default yang terhubung ke internet
    local main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$main_interface" ]; then
        # Fallback: mengambil interface pertama yang aktif (bukan lo)
        main_interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi
    echo "$main_interface"
}

# Fungsi untuk mendapatkan gateway
get_default_gateway() {
    local gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# Fungsi untuk mendapatkan IP yang tersedia
get_available_ip() {
    local interface=$1
    local gateway=$2
    
    # Mendapatkan network prefix dari gateway
    local network_prefix=$(echo "$gateway" | cut -d. -f1-3)
    
    # Mencoba beberapa IP dalam range yang sama dengan gateway
    for i in {10..20}; do
        local test_ip="${network_prefix}.$i"
        if ! ping -c1 -W1 "$test_ip" &>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # Fallback ke IP default jika tidak ada yang tersedia
    echo "${network_prefix}.10"
}

# Fungsi untuk konfigurasi IP Statis
configure_static_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    local gateway=$4
    local dns1=$5
    local dns2=$6

    info_msg "Menerapkan konfigurasi IP statis: $ip pada interface $interface"

    # Buat direktori netplan jika belum ada
    mkdir -p /etc/netplan

    # Backup file konfigurasi network yang ada
    if [ -f "/etc/netplan/00-installer-config.yaml" ]; then
        cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.backup
    fi

    # Buat konfigurasi netplan baru dengan format yang benar
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${interface}:
      dhcp4: false
      addresses:
        - ${ip}/${netmask}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns1}, ${dns2}]
EOF

    # Set permission yang benar
    chown root:root /etc/netplan/00-installer-config.yaml
    chmod 0600 /etc/netplan/00-installer-config.yaml

    # Generate dan terapkan konfigurasi
    netplan generate

    # Terapkan konfigurasi dengan penanganan error
    if ! netplan apply; then
        warning_msg "Mencoba menerapkan konfigurasi dalam mode debug..."
        netplan --debug apply
    fi

    # Tunggu sebentar untuk interface up
    sleep 5

    # Verifikasi koneksi
    if ping -c 1 ${gateway} > /dev/null 2>&1; then
        success_msg "Konfigurasi IP statis berhasil diterapkan"
        return 0
    else
        error_exit "Gagal menerapkan konfigurasi IP statis"
        if [ -f "/etc/netplan/00-installer-config.yaml.backup" ]; then
            mv /etc/netplan/00-installer-config.yaml.backup /etc/netplan/00-installer-config.yaml
            chmod 0600 /etc/netplan/00-installer-config.yaml
            netplan apply
        fi
        return 1
    fi
}

# Fungsi untuk memeriksa persyaratan sistem Wazuh
check_wazuh_system_requirements() {
    info_msg "Memeriksa persyaratan sistem untuk Wazuh..."
    
    # Periksa RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 4096 ]; then
        warning_msg "RAM kurang dari 4GB. Wazuh membutuhkan minimal 4GB RAM"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Periksa disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        warning_msg "Ruang disk kurang dari 20GB. Wazuh membutuhkan minimal 20GB free space"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Fungsi untuk menangani error Wazuh
handle_wazuh_error() {
    local error_msg="$1"
    error_exit "Wazuh Error: $error_msg"
}

# Fungsi untuk generate perintah instalasi agent Wazuh
generate_wazuh_agent_command() {
    local server_ip=$1
    local WAZUH_VERSION="4.7.5"
    local ARCHITECTURE="amd64"

    info_msg "Membuat generator perintah instalasi Wazuh Agent"
    echo "IP Server Wazuh: $server_ip"

    # Input nama agent
    echo "Masukkan nomor atau nama untuk agent (default: ubuntu-agent):"
    read agent_name
    if [ -z "$agent_name" ]; then
        agent_name="ubuntu-agent"
    fi

    # Generate perintah instalasi
    local install_command="wget https://packages.wazuh.com/${WAZUH_VERSION%.*}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb && sudo WAZUH_MANAGER='${server_ip}' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='${agent_name}' dpkg -i ./wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb"

    # Simpan perintah ke file
    cat > /root/install_wazuh_agent.sh << EOF
#!/bin/bash

# Script instalasi Wazuh Agent
# Generated pada: $(date)
# Server: $server_ip
# Agent Name: $agent_name

$install_command

# Start Wazuh Agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Check status
sudo systemctl status wazuh-agent
EOF

    chmod +x /root/install_wazuh_agent.sh

    success_msg "Script instalasi agent telah dibuat: /root/install_wazuh_agent.sh"
    echo "Perintah instalasi untuk agent:"
    echo "$install_command"
    echo "Atau gunakan script yang telah dibuat:"
    echo "scp /root/install_wazuh_agent.sh user@agent-ip:~/"
    echo "ssh user@agent-ip 'sudo bash ~/install_wazuh_agent.sh'"

    # Tampilkan ringkasan
    echo "Ringkasan Agent Installation:"
    echo "1. Server IP: $server_ip"
    echo "2. Agent Name: $agent_name"
    echo "3. Wazuh Version: $WAZUH_VERSION"
    echo "4. Architecture: $ARCHITECTURE"
    echo "5. Agent Group: default"
}

# Fungsi untuk instalasi Wazuh
install_wazuh() {
    info_msg "Memulai instalasi Wazuh..."
    
    # Deteksi otomatis konfigurasi jaringan
    info_msg "Mendeteksi konfigurasi jaringan..."

    # Deteksi interface utama
    INTERFACE=$(get_main_interface)
    success_msg "Interface terdeteksi: $INTERFACE"

    # Deteksi gateway
    GATEWAY=$(get_default_gateway)
    if [ -z "$GATEWAY" ]; then
        warning_msg "Tidak dapat mendeteksi gateway. Menggunakan default gateway"
        GATEWAY="192.168.1.1"
    fi
    success_msg "Gateway terdeteksi: $GATEWAY"

    # Set IP statis yang tersedia
    STATIC_IP=$(get_available_ip "$INTERFACE" "$GATEWAY")
    success_msg "IP statis yang akan digunakan: $STATIC_IP"

    # Set konfigurasi default
    NETMASK="24"
    DNS1="8.8.8.8"
    DNS2="8.8.4.4"

    # Periksa persyaratan sistem
    check_wazuh_system_requirements

    # Terapkan konfigurasi IP statis
    info_msg "Menerapkan konfigurasi IP statis..."
    configure_static_ip "$STATIC_IP" "$INTERFACE" "$NETMASK" "$GATEWAY" "$DNS1" "$DNS2"

    # Buat direktori untuk menyimpan file instalasi
    INSTALL_DIR="/root/wazuh-install-files"
    mkdir -p ${INSTALL_DIR}
    cd ${INSTALL_DIR}

    # Download Wazuh installer
    info_msg "Mengunduh Wazuh installer..."
    if ! curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh; then
        handle_wazuh_error "Gagal mengunduh installer Wazuh"
    fi

    chmod +x wazuh-install.sh

    # Membuat config.yml
    cat > config.yml << EOF
nodes:
  indexer:
    - name: node-1
      ip: ${STATIC_IP}
      role: master
  server:
    - name: wazuh-1
      ip: ${STATIC_IP}
  dashboard:
    - name: dashboard
      ip: ${STATIC_IP}
EOF

    # Buat direktori untuk menyimpan kredensial
    CRED_DIR="/root/wazuh-credentials"
    mkdir -p ${CRED_DIR}
    chmod 700 ${CRED_DIR}

    # Menjalankan instalasi dengan penanganan error
    success_msg "Memulai instalasi Wazuh..."

    # Generate config files
    if ! ./wazuh-install.sh --generate-config-files; then
        handle_wazuh_error "Gagal generate config files"
    fi
    success_msg "Konfigurasi berhasil di-generate"

    # Install dan start Wazuh indexer
    if ! ./wazuh-install.sh --wazuh-indexer node-1; then
        handle_wazuh_error "Gagal instalasi wazuh indexer"
    fi
    success_msg "Wazuh indexer berhasil diinstal"

    # Tunggu indexer siap
    info_msg "Menunggu Wazuh indexer siap..."
    sleep 30

    # Start cluster
    if ! ./wazuh-install.sh --start-cluster; then
        handle_wazuh_error "Gagal memulai cluster"
    fi
    success_msg "Cluster berhasil dimulai"

    # Simpan password
    info_msg "Menyimpan kredensial..."
    tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > ${CRED_DIR}/wazuh-passwords-full.txt
    chmod 600 ${CRED_DIR}/wazuh-passwords-full.txt

    # Install Wazuh server
    if ! ./wazuh-install.sh --wazuh-server wazuh-1; then
        handle_wazuh_error "Gagal instalasi wazuh server"
    fi
    success_msg "Wazuh server berhasil diinstal"

    # Tunggu server siap
    info_msg "Menunggu Wazuh server siap..."
    sleep 30

    # Install Wazuh dashboard
    if ! ./wazuh-install.sh --wazuh-dashboard dashboard; then
        handle_wazuh_error "Gagal instalasi wazuh dashboard"
    fi
    success_msg "Wazuh dashboard berhasil diinstal"

    # Ekstrak dan simpan password spesifik
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "admin" > ${CRED_DIR}/admin-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "wazuh" > ${CRED_DIR}/wazuh-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "kibana" > ${CRED_DIR}/kibana-passwords.txt

    # Buat file rangkuman kredensial
    cat > ${CRED_DIR}/credentials-summary.txt << EOF
Wazuh Credentials Summary
========================
Tanggal Instalasi: $(date)
IP Server: ${STATIC_IP}

Lokasi File Kredensial:
- Password Lengkap: ${CRED_DIR}/wazuh-passwords-full.txt
- Password Admin: ${CRED_DIR}/admin-passwords.txt
- Password Wazuh: ${CRED_DIR}/wazuh-passwords.txt
- Password Kibana: ${CRED_DIR}/kibana-passwords.txt

Akses Dashboard: https://${STATIC_IP}
Default username: admin

Note: 
- Simpan file ini di tempat yang aman
- Ganti password default setelah login pertama
- Backup folder ${CRED_DIR} secara berkala
EOF

    # Set permission untuk file kredensial
    chmod 600 ${CRED_DIR}/*
    chown -R root:root ${CRED_DIR}

    # Tambahkan entri ke /etc/hosts
    echo "${STATIC_IP} node-1 wazuh-1 dashboard" >> /etc/hosts

    # Periksa status layanan
    info_msg "Memeriksa status layanan..."
    services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            success_msg "Service $service berjalan dengan baik"
        else
            warning_msg "Service $service tidak berjalan"
            systemctl status $service
            info_msg "Mencoba restart service ${service}..."
            systemctl restart $service
            sleep 5
            if systemctl is-active --quiet $service; then
                success_msg "Service $service berhasil direstart"
            else
                warning_msg "Service $service masih bermasalah"
            fi
        fi
    done

    # Simpan informasi konfigurasi
    cat > /root/wazuh-info.txt << EOF
Konfigurasi Wazuh:
=================
IP Address: ${STATIC_IP}
Interface: ${INTERFACE}
Netmask: ${NETMASK}
Gateway: ${GATEWAY}
DNS1: ${DNS1}
DNS2: ${DNS2}

Dashboard URL: https://${STATIC_IP}

Lokasi File Kredensial: ${CRED_DIR}
EOF

    success_msg "Instalasi Wazuh selesai!"
    echo "Anda dapat mengakses dashboard di: https://${STATIC_IP}"
    echo "Kredensial tersimpan di: ${CRED_DIR}"
    echo "Informasi konfigurasi tersimpan di: /root/wazuh-info.txt"

    # Generate script instalasi agent
    info_msg "Membuat script instalasi untuk Wazuh Agent..."
    generate_wazuh_agent_command "${STATIC_IP}"

    success_msg "Proses instalasi dan konfigurasi Wazuh selesai!"
    
    # Return ke direktori asal
    cd "$SCRIPT_DIR"
}

# ==============================================================================
# FUNGSI INSTALASI MISP
# ==============================================================================

# Function to check MISP dependencies
check_misp_dependencies() {
    info_msg "Checking MISP dependencies..."
    if ! command -v docker &> /dev/null; then
        error_exit "Error: 'docker' is not installed. Please install Docker first."
    fi
    if ! command -v docker-compose &> /dev/null; then
        error_exit "Error: 'docker-compose' is not installed. Please install Docker Compose first."
    fi
    success_msg "MISP dependencies are satisfied."
}

# Function to wait for MISP to become available
wait_for_misp() {
    info_msg "Waiting for MISP to become available... This may take several minutes."
    until curl --output /dev/null --silent --head --fail --insecure https://localhost; do
        printf '.'
        sleep 5
    done
    success_msg "MISP is up and running!"
}

# Function to install and setup MISP
install_misp() {
    info_msg "Memulai instalasi MISP..."
    
    # MISP Configuration
    MISP_INSTALL_DIR="/opt/misp-docker"
    MISP_DOCKER_COMPOSE_URL="https://raw.githubusercontent.com/misp/misp-docker/main/docker-compose.yml"
    
    # Detail untuk pengguna API yang akan dibuat
    ORG_NAME="Wazuh-IR-Automation"
    USER_EMAIL_FOR_KEY="wazuh-automation@localhost.local"
    USER_COMMENT="API key for Wazuh Active Response integration"
    
    check_misp_dependencies
    
    # Periksa apakah kontainer MISP sudah berjalan
    MISP_CONTAINER_ID=$(docker ps -q --filter "name=misp-server")
    
    if [ -z "$MISP_CONTAINER_ID" ]; then
        info_msg "MISP container not found. Starting installation process..."
        
        # 1. Buat direktori instalasi
        info_msg "Creating installation directory at ${MISP_INSTALL_DIR}..."
        run_command "mkdir -p '$MISP_INSTALL_DIR'" "Creating MISP installation directory"
        cd "$MISP_INSTALL_DIR"
        
        # 2. Unduh file docker-compose.yml
        info_msg "Downloading latest misp-docker docker-compose.yml..."
        run_command "curl -o docker-compose.yml '$MISP_DOCKER_COMPOSE_URL'" "Downloading MISP docker-compose file"
        
        # 3. Jalankan MISP menggunakan docker-compose
        info_msg "Starting MISP containers in detached mode (-d)..."
        run_command "docker-compose up -d" "Starting MISP containers"
        
        # 4. Tunggu hingga MISP benar-benar siap
        wait_for_misp
        
        success_msg "MISP installation completed successfully."
    else
        success_msg "MISP is already installed and running."
        # Pastikan kita berada di direktori yang benar untuk perintah exec
        cd "$MISP_INSTALL_DIR"
    fi
    
    # Pengambilan API Key
    info_msg "Attempting to create/retrieve API key for user '${USER_EMAIL_FOR_KEY}'..."
    
    # Dapatkan email admin default dari dalam kontainer
    ADMIN_EMAIL=$(docker-compose exec -T misp-server cat /var/www/MISP/app/Config/config.php | grep "'email' =>" | head -1 | sed "s/.*'email' => '\([^']*\)'.*/\1/")
    
    if [ -z "$ADMIN_EMAIL" ]; then
        warning_msg "Could not automatically determine admin email. Defaulting to 'admin@admin.test'."
        ADMIN_EMAIL="admin@admin.test"
    fi
    
    info_msg "Using admin email: ${ADMIN_EMAIL}"
    
    # Gunakan perintah 'cake' di dalam kontainer untuk membuat pengguna dan mendapatkan kuncinya
    API_KEY_OUTPUT=$(docker-compose exec -T misp-server \
        /var/www/MISP/app/Console/cake Admin setApiUser "$ADMIN_EMAIL" "$ORG_NAME" "$USER_EMAIL_FOR_KEY" "$USER_COMMENT")
    
    # Ekstrak kunci API dari output
    MISP_KEY=$(echo "$API_KEY_OUTPUT" | grep 'Auth key:' | awk '{print $3}')
    
    if [ -n "$MISP_KEY" ]; then
        success_msg "Successfully retrieved API Key!"
        echo "------------------------------------------------------------------"
        echo "Your MISP API Key is: $MISP_KEY"
        echo "------------------------------------------------------------------"
        echo "Simpan kunci ini di tempat yang aman. Anda akan membutuhkannya untuk"
        echo "mengkonfigurasi skrip integrasi Wazuh."
        
        # Update config.conf dengan API key yang baru
        if [ -f "/etc/soc-config/config.conf" ]; then
            sed -i "s/MISP_KEY=.*/MISP_KEY=\"$MISP_KEY\"/" /etc/soc-config/config.conf
            success_msg "MISP API Key berhasil diupdate di config.conf"
        fi
    else
        error_exit "Error: Failed to retrieve API Key."
        info_msg "Please check the logs using 'docker-compose logs -f' in '${MISP_INSTALL_DIR}'."
    fi
    
    success_msg "MISP setup completed successfully!"
}

# ==============================================================================
# FUNGSI INSTALASI SERVER MONITORING
# ==============================================================================

# Function to setup monitoring server (backup repository)
install_monitoring_server() {
    info_msg "Memulai instalasi Server Monitoring (Backup Repository)..."
    
    # Tentukan direktori untuk menyimpan backup
    info_msg "Menentukan direktori untuk menyimpan backup Git dan arsip dinamis..."
    read -r -p "Masukkan path direktori utama backup (default: /var/backup/web_backups): " MAIN_BACKUP_DIR
    MAIN_BACKUP_DIR=${MAIN_BACKUP_DIR:-/var/backup/web_backups}

    # Path untuk backup Git (repositori bare)
    GIT_BACKUP_SUBDIR="git_repo" # Nama subdirektori untuk Git
    ACTUAL_GIT_BACKUP_PATH="$MAIN_BACKUP_DIR/$GIT_BACKUP_SUBDIR"

    # Path untuk backup file dinamis (arsip .tar.gz)
    DYNAMIC_BACKUP_SUBDIR="dynamic_archives" # Nama subdirektori untuk arsip dinamis
    ACTUAL_DYNAMIC_BACKUP_PATH="$MAIN_BACKUP_DIR/$DYNAMIC_BACKUP_SUBDIR"

    # Buat direktori backup jika belum ada
    if [ ! -d "$ACTUAL_GIT_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup Git: $ACTUAL_GIT_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_GIT_BACKUP_PATH'" "Creating Git backup directory"
    fi
    if [ ! -d "$ACTUAL_DYNAMIC_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup dinamis: $ACTUAL_DYNAMIC_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_DYNAMIC_BACKUP_PATH'" "Creating dynamic backup directory"
    fi

    # Membuat pengguna khusus untuk backup
    echo ""
    info_msg "Pengaturan Pengguna Khusus untuk Menerima Backup"
    echo "----------------------------------------------------"
    read -r -p "Apakah Anda ingin membuat pengguna sistem khusus untuk menerima backup via SSH? (y/n, default: y): " CREATE_USER
    CREATE_USER=${CREATE_USER:-y}

    BACKUP_USER="" # Akan diisi jika CREATE_USER=y

    if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]]; then
        read -r -p "Masukkan nama pengguna untuk backup (default: webbackupuser): " INPUT_BACKUP_USER
        BACKUP_USER=${INPUT_BACKUP_USER:-webbackupuser}
        
        if id "$BACKUP_USER" &>/dev/null; then
            info_msg "Pengguna '$BACKUP_USER' sudah ada."
        else
            info_msg "Membuat pengguna '$BACKUP_USER'..."
            run_command "useradd -r -m -s /bin/bash '$BACKUP_USER'" "Creating backup user"
            success_msg "Pengguna '$BACKUP_USER' berhasil dibuat."
        fi
        
        info_msg "Mengatur kepemilikan direktori backup untuk pengguna '$BACKUP_USER'..."
        run_command "chown -R '$BACKUP_USER:$BACKUP_USER' '$MAIN_BACKUP_DIR'" "Setting ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting permissions of backup directory"

        # Inisialisasi repository Git bare
        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH'..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
            read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        
        # Mengatur SSH untuk pengguna backup
        USER_SSH_DIR="/home/$BACKUP_USER/.ssh"
        info_msg "Memastikan direktori SSH '$USER_SSH_DIR' dan 'authorized_keys' ada untuk pengguna '$BACKUP_USER'..."
        run_command "sudo -u '$BACKUP_USER' mkdir -p '$USER_SSH_DIR'" "Creating SSH directory for backup user"
        run_command "sudo -u '$BACKUP_USER' touch '$USER_SSH_DIR/authorized_keys'" "Creating authorized_keys file"
        run_command "sudo -u '$BACKUP_USER' chmod 700 '$USER_SSH_DIR'" "Setting SSH directory permissions"
        run_command "sudo -u '$BACKUP_USER' chmod 600 '$USER_SSH_DIR/authorized_keys'" "Setting authorized_keys permissions"
        success_msg "Setup direktori SSH untuk '$BACKUP_USER' selesai."
        
        echo ""
        info_msg "--- INSTRUKSI PENTING UNTUK SERVER WEB ---"
        echo "Untuk mengizinkan server web melakukan push backup ke server monitoring ini:"
        echo "1. Di SERVER WEB, pastikan Anda memiliki SSH key pair untuk user root (atau user yang menjalankan backup)."
        echo "   Kunci publiknya (biasanya di '/root/.ssh/id_rsa_web_backup.pub') perlu disalin."
        echo "2. Di SERVER MONITORING INI, tambahkan isi kunci publik tersebut ke dalam file:"
        echo "   $USER_SSH_DIR/authorized_keys"
        echo "3. Pastikan pengguna '$BACKUP_USER' adalah pemilik file tersebut dan memiliki izin yang benar (chmod 600)."
        echo "--------------------------------------------"

    else # Jika tidak membuat pengguna khusus, backup akan diterima oleh root
        BACKUP_USER="root" # Backup akan menggunakan root jika tidak ada user khusus
        warning_msg "PERINGATAN: Tidak ada pengguna khusus yang dibuat. Backup akan diterima sebagai pengguna 'root'. Ini kurang aman."
        info_msg "Pastikan direktori '$MAIN_BACKUP_DIR' dapat ditulis oleh root."
        run_command "chown -R 'root:root' '$MAIN_BACKUP_DIR'" "Setting root ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting root permissions of backup directory"

        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH' sebagai root..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
             read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository as root"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository as root"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        info_msg "SSH key dari server web perlu ditambahkan ke '/root/.ssh/authorized_keys' di server monitoring ini."
    fi

    # Konfigurasi Monitoring Server Ini Sendiri (Opsional)
    echo ""
    info_msg "Konfigurasi Monitoring untuk Server Backup Ini Sendiri (Opsional)"
    echo "-------------------------------------------------------------------"
    read -r -p "Apakah Anda ingin menginstal Wazuh Agent untuk memonitor server backup ini sendiri? (y/n, default: n): " INSTALL_WAZUH_AGENT_LOCAL
    INSTALL_WAZUH_AGENT_LOCAL=${INSTALL_WAZUH_AGENT_LOCAL:-n}

    if [[ "$INSTALL_WAZUH_AGENT_LOCAL" == "y" || "$INSTALL_WAZUH_AGENT_LOCAL" == "Y" ]]; then
        info_msg "Memulai instalasi Wazuh Agent untuk server backup ini..."
        
        if ! command -v apt-key &> /dev/null || ! command -v tee &> /dev/null ; then
            run_command "apt-get install -y gnupg apt-transport-https" "Installing gnupg and apt-transport-https"
        fi

        run_command "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg" "Importing Wazuh GPG key"
        run_command "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list" "Adding Wazuh repository"
        
        run_command "apt-get update -y" "Updating package list after adding Wazuh repository"
        run_command "apt-get install -y wazuh-agent" "Installing Wazuh Agent"
        
        read -r -p "Masukkan alamat IP Wazuh Manager untuk agent ini: " WAZUH_MANAGER_IP_FOR_AGENT
        while [[ -z "$WAZUH_MANAGER_IP_FOR_AGENT" ]]; do
            read -r -p "Alamat IP Wazuh Manager tidak boleh kosong. Masukkan IP: " WAZUH_MANAGER_IP_FOR_AGENT
        done
        
        # Konfigurasi Wazuh Agent (ossec.conf)
        run_command "sed -i 's|<address>MANAGER_IP</address>|<address>$WAZUH_MANAGER_IP_FOR_AGENT</address>|g' /var/ossec/etc/ossec.conf" "Configuring Wazuh Agent manager IP"
        
        run_command "systemctl daemon-reload" "Reloading systemd daemon"
        run_command "systemctl enable wazuh-agent" "Enabling Wazuh Agent service"
        run_command "systemctl restart wazuh-agent" "Starting Wazuh Agent service"
        
        success_msg "Wazuh Agent berhasil diinstal dan dikonfigurasi untuk memonitor server backup ini."
        info_msg "Pastikan untuk mendaftarkan agent ini di Wazuh Manager."
    else
        info_msg "Instalasi Wazuh Agent untuk server backup ini dilewati."
    fi

    # Konfigurasi Git Hooks untuk Notifikasi (opsional)
    echo ""
    info_msg "Konfigurasi Git Hook untuk Notifikasi Email (Opsional)"
    echo "---------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur notifikasi email setiap kali backup Git diterima? (y/n, default: n): " SETUP_NOTIFICATION
    SETUP_NOTIFICATION=${SETUP_NOTIFICATION:-n}

    if [[ "$SETUP_NOTIFICATION" == "y" || "$SETUP_NOTIFICATION" == "Y" ]]; then
        if ! command -v mail &> /dev/null; then
            info_msg "Command 'mail' (mailutils) tidak ditemukan. Menginstal..."
            run_command "apt-get install -y mailutils" "Installing mailutils for email notifications"
        fi

        if command -v mail &> /dev/null; then
            read -r -p "Masukkan alamat email untuk notifikasi: " NOTIFY_EMAIL
            while [[ -z "$NOTIFY_EMAIL" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " NOTIFY_EMAIL
            done
            
            HOOK_DIR="$ACTUAL_GIT_BACKUP_PATH/hooks"
            HOOK_FILE="$HOOK_DIR/post-receive"

            info_msg "Membuat direktori hook $HOOK_DIR jika belum ada..."
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "sudo -u '$BACKUP_USER' mkdir -p '$HOOK_DIR'" "Creating hook directory as backup user"
            else
                run_command "mkdir -p '$HOOK_DIR'" "Creating hook directory"
            fi

            info_msg "Membuat skrip post-receive hook di $HOOK_FILE..."
            cat > "$HOOK_FILE" << EOF_HOOK
#!/bin/bash
# Git hook untuk mengirim notifikasi email saat menerima backup baru

REPO_NAME="\$(basename "\$(pwd)")"
COMMIT_INFO=\$(git log -1 --pretty=format:"%h - %an, %ar : %s")
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=\$(date +"%Y-%m-%d %H:%M:%S")

mail -s "Backup GIT Baru Diterima di \$SERVER_HOSTNAME untuk \$REPO_NAME" "$NOTIFY_EMAIL" << EOM_MAIL
Backup Git baru telah diterima di server monitoring: \$SERVER_HOSTNAME

Repository Path: \$(pwd)
Timestamp: \$TIMESTAMP
Commit Terakhir: \$COMMIT_INFO

Pesan ini dikirim otomatis dari hook post-receive.
EOM_MAIL
EOF_HOOK

            run_command "chmod +x '$HOOK_FILE'" "Making hook file executable"
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "chown '$BACKUP_USER:$BACKUP_USER' '$HOOK_FILE'" "Setting hook file ownership to backup user"
                info_msg "Kepemilikan hook diatur ke $BACKUP_USER."
            fi
            success_msg "Notifikasi email untuk backup Git baru telah dikonfigurasi di $HOOK_FILE."
            info_msg "Pastikan MTA (seperti Postfix atau ssmtp) terkonfigurasi di server ini agar perintah 'mail' berfungsi."
        else
            warning_msg "Gagal menginstal atau menemukan 'mail'. Notifikasi email dilewati."
        fi
    fi

    # Monitoring disk space untuk MAIN_BACKUP_DIR (opsional)
    echo ""
    info_msg "Monitoring Disk Space untuk Direktori Backup (Opsional)"
    echo "-----------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur monitoring disk space untuk '$MAIN_BACKUP_DIR'? (y/n, default: y): " SETUP_DISK_MONITORING
    SETUP_DISK_MONITORING=${SETUP_DISK_MONITORING:-y}

    if [[ "$SETUP_DISK_MONITORING" == "y" || "$SETUP_DISK_MONITORING" == "Y" ]]; then
        if ! command -v mail &> /dev/null && ! command -v mailx &> /dev/null ; then
            info_msg "Command 'mail' atau 'mailx' tidak ditemukan. Menginstal mailutils..."
            run_command "apt-get install -y mailutils" "Installing mailutils for disk monitoring"
        fi

        if command -v mail &> /dev/null || command -v mailx &> /dev/null ; then
            MONITOR_SCRIPT_PATH="/usr/local/bin/monitor_backup_disk_space.sh"
            info_msg "Membuat skrip monitoring disk di $MONITOR_SCRIPT_PATH..."

            cat > "$MONITOR_SCRIPT_PATH" << EOF_DISK_MON
#!/bin/bash
# Skrip untuk memonitor penggunaan disk direktori backup

TARGET_BACKUP_DIR="\$1"
USAGE_THRESHOLD="\$2" # Persentase, misal 80
EMAIL_RECIPIENT="\$3"
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
LOG_FILE="/var/log/backup_disk_monitor.log"
MAIL_COMMAND=\$(command -v mail || command -v mailx)

if [ -z "\$MAIL_COMMAND" ]; then
    echo "[\$(date)] Error: Perintah mail/mailx tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

if [ ! -d "\$TARGET_BACKUP_DIR" ]; then
    echo "[\$(date)] Error: Direktori backup '\$TARGET_BACKUP_DIR' tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

CURRENT_USAGE=\$(df "\$TARGET_BACKUP_DIR" | awk 'NR==2 {print \$5}' | sed 's/%//')

if [ -z "\$CURRENT_USAGE" ]; then
    echo "[\$(date)] Error: Tidak dapat mengambil info penggunaan disk untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
    exit 1
fi

if [ "\$CURRENT_USAGE" -gt "\$USAGE_THRESHOLD" ]; then
    SUBJECT="[PERINGATAN] Disk Backup di \$SERVER_HOSTNAME Hampir Penuh (\$CURRENT_USAGE%)"
    MESSAGE="Penggunaan disk pada direktori backup '\$TARGET_BACKUP_DIR' di server \$SERVER_HOSTNAME telah mencapai \$CURRENT_USAGE% (Threshold: \$USAGE_THRESHOLD%).\n\nDetail Penggunaan Disk:\n\$(df -h "\$TARGET_BACKUP_DIR")\n\nHarap segera periksa dan kosongkan ruang jika perlu."
    
    echo -e "\$MESSAGE" | \$MAIL_COMMAND -s "\$SUBJECT" "\$EMAIL_RECIPIENT"
    echo "[\$(date)] Peringatan Terkirim: Penggunaan disk \$CURRENT_USAGE% melebihi threshold \$USAGE_THRESHOLD% untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
else
    echo "[\$(date)] Info: Penggunaan disk \$CURRENT_USAGE% untuk '\$TARGET_BACKUP_DIR' masih di bawah threshold \$USAGE_THRESHOLD%." >> "\$LOG_FILE"
fi
exit 0
EOF_DISK_MON
            run_command "chmod +x '$MONITOR_SCRIPT_PATH'" "Making disk monitoring script executable"
            success_msg "Skrip monitoring disk $MONITOR_SCRIPT_PATH berhasil dibuat."

            read -r -p "Masukkan threshold penggunaan disk dalam persen (misal 80, default: 80): " DISK_THRESHOLD_INPUT
            DISK_THRESHOLD_INPUT=${DISK_THRESHOLD_INPUT:-80}
            read -r -p "Masukkan alamat email untuk notifikasi disk space: " DISK_EMAIL_INPUT
            while [[ -z "$DISK_EMAIL_INPUT" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " DISK_EMAIL_INPUT
            done
            
            CRON_DISK_MON_ENTRY="0 7 * * * $MONITOR_SCRIPT_PATH \"$MAIN_BACKUP_DIR\" \"$DISK_THRESHOLD_INPUT\" \"$DISK_EMAIL_INPUT\""
            
            # Tambahkan ke crontab root
            run_command "(crontab -l 2>/dev/null | grep -vF '$MONITOR_SCRIPT_PATH'; echo '$CRON_DISK_MON_ENTRY') | crontab -" "Adding disk monitoring to crontab"
            success_msg "Monitoring disk space untuk direktori backup '$MAIN_BACKUP_DIR' telah diatur via cron."
            info_msg "Log monitoring disk akan ada di /var/log/backup_disk_monitor.log"
        else
            warning_msg "Gagal menginstal atau menemukan 'mail/mailx'. Monitoring disk space dilewati."
        fi
    fi

    SERVER_IP_ADDRESS=$(hostname -I | awk '{print $1}') # Ambil IP utama

    echo ""
    echo "================================================================="
    echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
    echo "================================================================="
    echo ""
    echo "Informasi Penting untuk Konfigurasi Server Web:"
    echo "----------------------------------------------"
    echo "IP Server Monitoring Ini: ${SERVER_IP_ADDRESS:-Mohon periksa manual}"
    echo "Pengguna SSH untuk Backup: $BACKUP_USER"
    echo "Path Tujuan Backup Git: $ACTUAL_GIT_BACKUP_PATH"
    echo "Path Tujuan Backup Dinamis (arsip): $ACTUAL_DYNAMIC_BACKUP_PATH"
    echo ""
    echo "Contoh Perintah di Server Web untuk Menambahkan Remote Git:"
    echo "   git remote add monitoring $BACKUP_USER@${SERVER_IP_ADDRESS:-<IP_SERVER_MONITORING>}:$ACTUAL_GIT_BACKUP_PATH"
    echo ""
    echo "CATATAN PENTING:"
    echo "- Format URL Git SSH yang disarankan: '$BACKUP_USER@<IP_SERVER_MONITORING>:$ACTUAL_GIT_BACKUP_PATH' (gunakan path absolut)."
    echo "- Pastikan kunci SSH publik dari server web (user root atau yang menjalankan backup) telah ditambahkan ke:"
    echo "  '/home/$BACKUP_USER/.ssh/authorized_keys' (jika $BACKUP_USER dibuat) atau '/root/.ssh/authorized_keys' (jika tidak ada user khusus) di server monitoring ini."
    echo "- Pastikan direktori '$ACTUAL_DYNAMIC_BACKUP_PATH' dapat ditulis oleh '$BACKUP_USER' (atau root) melalui rsync/scp."
    echo ""
    echo "Server monitoring ini sekarang siap menerima backup."
    echo "================================================================="
}

# ==============================================================================
# FUNGSI KONFIGURASI SOC
# ==============================================================================

# Function to collect user input for configuration
collect_user_config() {
    info_msg "Mengumpulkan konfigurasi dari user..."
    
    # Web directory
    read -r -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
    WEB_DIR=${WEB_DIR:-/var/www/html}
    
    # Backup directory
    read -r -p "Masukkan path direktori backup (default: /var/soc-backup): " BACKUP_DIR
    BACKUP_DIR=${BACKUP_DIR:-/var/soc-backup}
    
    # Quarantine directory
    read -r -p "Masukkan path direktori karantina (default: /var/soc-quarantine): " QUARANTINE_DIR
    QUARANTINE_DIR=${QUARANTINE_DIR:-/var/soc-quarantine}
    
    # Log directory
    read -r -p "Masukkan path direktori log (default: /var/log/soc-incident-response): " LOG_DIR
    LOG_DIR=${LOG_DIR:-/var/log/soc-incident-response}
    
    # Wazuh alerts file
    read -r -p "Masukkan path file alerts Wazuh (default: /var/ossec/logs/alerts/alerts.json): " WAZUH_ALERTS_FILE
    WAZUH_ALERTS_FILE=${WAZUH_ALERTS_FILE:-/var/ossec/logs/alerts/alerts.json}
    
    # Rule IDs
    read -r -p "Masukkan Rule IDs untuk defacement (default: 550,554,5501,5502,5503,5504,100001,100002): " DEFACE_RULE_IDS
    DEFACE_RULE_IDS=${DEFACE_RULE_IDS:-550,554,5501,5502,5503,5504,100001,100002}
    
    read -r -p "Masukkan Rule IDs untuk serangan (default: 5710,5712,5715,5760,100003,100004): " ATTACK_RULE_IDS
    ATTACK_RULE_IDS=${ATTACK_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk eradication (default: 5710,5712,5715,5760,100003,100004): " ERADICATION_RULE_IDS
    ERADICATION_RULE_IDS=${ERADICATION_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk restore (default: 100010,100011,100012): " RESTORE_RULE_IDS
    RESTORE_RULE_IDS=${RESTORE_RULE_IDS:-100010,100011,100012}
    
    # MISP Configuration
    read -r -p "Masukkan URL MISP (default: https://192.168.28.135): " MISP_URL
    MISP_URL=${MISP_URL:-https://192.168.28.135}
    
    read -r -p "Masukkan API Key MISP: " MISP_KEY
    if [[ -z "$MISP_KEY" ]]; then
        MISP_KEY="XweOnEWOtWFmIbW585H2m03R3SIZRmIKxrza73WB"
        warning_msg "Menggunakan API Key default MISP"
    fi
    
    read -r -p "Verifikasi sertifikat MISP? (y/n, default: n): " MISP_VERIFY_CERT
    if [[ "$MISP_VERIFY_CERT" =~ ^[Yy]$ ]]; then
        MISP_VERIFY_CERT="true"
    else
        MISP_VERIFY_CERT="false"
    fi
    
    # Monitoring server
    while true; do
        read -r -p "Masukkan IP server monitoring (default: 192.168.1.100): " MONITORING_SERVER
        MONITORING_SERVER=${MONITORING_SERVER:-192.168.1.100}
        if validate_ip "$MONITORING_SERVER"; then
            break
        else
            warning_msg "IP address tidak valid. Silakan coba lagi."
        fi
    done
    
    read -r -p "Masukkan username server monitoring (default: soc-backup): " MONITORING_USER
    MONITORING_USER=${MONITORING_USER:-soc-backup}
    
    read -s -p "Masukkan password server monitoring: " MONITORING_PASSWORD
    echo
    
    # Backup paths
    read -r -p "Masukkan path backup remote (default: /home/soc-backup/backups): " REMOTE_BACKUP_PATH
    REMOTE_BACKUP_PATH=${REMOTE_BACKUP_PATH:-/home/soc-backup/backups}
    
    # Web server user/group
    read -r -p "Masukkan user web server (default: www-data): " WEB_SERVER_USER
    WEB_SERVER_USER=${WEB_SERVER_USER:-www-data}
    
    read -r -p "Masukkan group web server (default: www-data): " WEB_SERVER_GROUP
    WEB_SERVER_GROUP=${WEB_SERVER_GROUP:-www-data}
    
    # Password untuk restore
    read -s -p "Masukkan password untuk restore (minimal 12 karakter): " RESTORE_PASSWORD
    echo
    if [[ ${#RESTORE_PASSWORD} -lt 12 ]]; then
        error_exit "Password harus minimal 12 karakter"
    fi
    ENCODED_PASSWORD=$(echo -n "$RESTORE_PASSWORD" | base64)
    
    success_msg "Konfigurasi user berhasil dikumpulkan"
}

# Function to create config.conf from user input
create_config_file() {
    info_msg "Membuat file config.conf..."
    
    local config_dir="/etc/soc-config"
    run_command "mkdir -p '$config_dir'" "Creating SOC config directory"
    
    cat > "$config_dir/config.conf" << EOF
# =================================================================
# SOC INCIDENT RESPONSE CONFIGURATION - NIST 800-61r2 FRAMEWORK
# =================================================================
# File konfigurasi terpusat untuk semua script IRLC
# Sesuai dengan NIST 800-61r2: Preparation, Detection & Analysis, 
# Containment, Eradication, Recovery, dan Post-Incident Activity

# =================================================================
# PREPARATION PHASE - Konfigurasi Dasar Sistem
# =================================================================

# Direktori web yang akan diproteksi
WEB_DIR="$WEB_DIR"

# Direktori backup utama
BACKUP_DIR="$BACKUP_DIR"

# Direktori karantina untuk file mencurigakan
QUARANTINE_DIR="$QUARANTINE_DIR"

# Direktori log untuk semua aktivitas IRLC
LOG_DIR="$LOG_DIR"

# Direktori konfigurasi SOC
SOC_CONFIG_DIR="$config_dir"

# =================================================================
# DETECTION & ANALYSIS PHASE - Wazuh Integration
# =================================================================

# File alerts.json utama Wazuh
WAZUH_ALERTS_FILE="$WAZUH_ALERTS_FILE"

# Direktori log Wazuh active response
WAZUH_ACTIVE_RESPONSE_LOG_DIR="/var/log/wazuh/active-response"

# Rule IDs untuk deteksi defacement
DEFACE_RULE_IDS="$DEFACE_RULE_IDS"

# Rule IDs untuk deteksi serangan
ATTACK_RULE_IDS="$ATTACK_RULE_IDS"

# Rule IDs untuk trigger eradication
ERADICATION_RULE_IDS="$ERADICATION_RULE_IDS"

# Rule IDs untuk trigger auto restore
RESTORE_RULE_IDS="$RESTORE_RULE_IDS"

# =================================================================
# CONTAINMENT PHASE - Network & System Isolation
# =================================================================

# File untuk mencatat IP yang diblokir
BLOCKED_IPS_FILE="$LOG_DIR/blocked_ips.txt"

# File halaman maintenance
MAINTENANCE_PAGE_FILENAME="maintenance.html"

# File index utama
INDEX_FILENAME="index.html"

# =================================================================
# ERADICATION PHASE - Threat Removal
# =================================================================

# Direktori YARA rules
YARA_RULES_DIR="/var/ossec/etc/rules/yara"

# Socket path ClamAV daemon
CLAMD_SOCKET="/var/run/clamav/clamd.ctl"

# Pattern mencurigakan untuk deteksi (pisahkan dengan |||)
ERADICATION_SUSPICIOUS_PATTERNS="(?i)(eval\s*\(base64_decode\s*\()|||(?i)(passthru\s*\()|||(?i)(shell_exec\s*\()|||(?i)(system\s*\()|||(?i)(exec\s*\()|||(?i)(preg_replace\s*\(.*\/e\s*\))|||(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)|||(?i)(document\.write\s*\(\s*unescape\s*\()|||(?i)(<iframe\s*src\s*=\s*[\"']javascript:)|||(?i)(fsockopen|pfsockopen)\s*\("

# =================================================================
# RECOVERY PHASE - System Restoration
# =================================================================

# Password untuk restore (base64 encoded)
PASSWORD="$ENCODED_PASSWORD"

# Konfigurasi monitoring server
MONITOR_IP="$MONITORING_SERVER"
MONITOR_USER="$MONITORING_USER"
MONITORING_SERVER="$MONITORING_SERVER"
MONITORING_USER="$MONITORING_USER"
MONITORING_PASSWORD="$MONITORING_PASSWORD"

# Path backup remote
REMOTE_GIT_BACKUP_PATH="/home/soc-backup/git-backup"
REMOTE_BACKUP_PATH="$REMOTE_BACKUP_PATH"
REMOTE_DYNAMIC_BACKUP_PATH="/home/soc-backup/dynamic-backup"

# File identitas SSH
SSH_IDENTITY_FILE="/home/soc-backup/.ssh/id_rsa"

# Cache direktori untuk restore dinamis
LOCAL_DYNAMIC_RESTORE_CACHE_DIR="/tmp/soc-dynamic-restore-cache"

# Backup dinamis aktif (true/false)
BACKUP_DYNAMIC="true"

# Direktori dinamis yang akan di-backup (array bash format)
DYNAMIC_DIRS=("uploads" "cache" "temp" "logs")

# User dan group web server
WEB_SERVER_USER="$WEB_SERVER_USER"
WEB_SERVER_GROUP="$WEB_SERVER_GROUP"

# =================================================================
# POST-INCIDENT ACTIVITY - Documentation & Analysis
# =================================================================

# Konfigurasi MISP untuk threat intelligence
MISP_URL="$MISP_URL"
MISP_KEY="$MISP_KEY"
MISP_VERIFY_CERT="$MISP_VERIFY_CERT"

# Direktori untuk laporan insiden
INCIDENT_REPORTS_DIR="$LOG_DIR/reports"

# File audit log
AUDIT_LOG="$LOG_DIR/audit.log"

# File log untuk MISP integration
MISP_LOG_FILE="$LOG_DIR/misp.log"

# =================================================================
# OUTPUT FILES - File Output untuk Setiap Fase
# =================================================================

# File output untuk deteksi IoC
DETECTION_OUTPUT_FILE="/tmp/active_response_500550.log"
DETECTION_LOG_FILE="/tmp/find_last_500550_debug.log"
IOC_DATA_FILE="/tmp/detected_ioc_data.json"

# File output untuk containment
CONTAINMENT_LOG_FILE="/var/log/wazuh/active-response/containment.log"

# File output untuk eradication
ERADICATION_LOG_FILE="/var/log/wazuh/active-response/eradication.log"

# File output untuk restore
RESTORE_LOG_FILE="/var/log/wazuh/active-response/restore.log"
RESTORE_AUTO_LOG_FILE="/var/log/wazuh/active-response/restore_auto.log"

# =================================================================
# SYSTEM INTEGRATION - Integrasi dengan Sistem
# =================================================================

# Timeout untuk operasi (dalam detik)
COMMAND_TIMEOUT="300"
RESTORE_TIMEOUT="600"

# Retry attempts untuk operasi yang gagal
MAX_RETRY_ATTEMPTS="3"

# Interval retry (dalam detik)
RETRY_INTERVAL="30"

# =================================================================
# SECURITY SETTINGS - Pengaturan Keamanan
# =================================================================

# Mode debug (true/false)
DEBUG_MODE="false"

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL="INFO"

# Enkripsi backup (true/false)
ENCRYPT_BACKUP="false"

# Backup retention days
BACKUP_RETENTION_DAYS="30"
EOF

    # Set permissions
    run_command "chmod 600 '$config_dir/config.conf'" "Setting config file permissions"
    run_command "chown root:root '$config_dir/config.conf'" "Setting config file ownership"
    
    # Create symbolic link for backward compatibility
    run_command "mkdir -p '/etc/web-backup'" "Creating web-backup config directory"
    run_command "ln -sf '$config_dir/config.conf' '/etc/web-backup/config.conf'" "Creating symbolic link for backward compatibility"
    
    success_msg "File config.conf berhasil dibuat di $config_dir/config.conf"
}

# ==============================================================================
# FUNGSI INSTALASI WAZUH
# ==============================================================================

# Fungsi untuk mendapatkan interface utama
get_main_interface() {
    # Mendapatkan interface default yang terhubung ke internet
    local main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$main_interface" ]; then
        # Fallback: mengambil interface pertama yang aktif (bukan lo)
        main_interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi
    echo "$main_interface"
}

# Fungsi untuk mendapatkan gateway
get_default_gateway() {
    local gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# Fungsi untuk mendapatkan IP yang tersedia
get_available_ip() {
    local interface=$1
    local gateway=$2
    
    # Mendapatkan network prefix dari gateway
    local network_prefix=$(echo "$gateway" | cut -d. -f1-3)
    
    # Mencoba beberapa IP dalam range yang sama dengan gateway
    for i in {10..20}; do
        local test_ip="${network_prefix}.$i"
        if ! ping -c1 -W1 "$test_ip" &>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # Fallback ke IP default jika tidak ada yang tersedia
    echo "${network_prefix}.10"
}

# Fungsi untuk konfigurasi IP Statis
configure_static_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    local gateway=$4
    local dns1=$5
    local dns2=$6

    info_msg "Menerapkan konfigurasi IP statis: $ip pada interface $interface"

    # Buat direktori netplan jika belum ada
    mkdir -p /etc/netplan

    # Backup file konfigurasi network yang ada
    if [ -f "/etc/netplan/00-installer-config.yaml" ]; then
        cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.backup
    fi

    # Buat konfigurasi netplan baru dengan format yang benar
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${interface}:
      dhcp4: false
      addresses:
        - ${ip}/${netmask}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns1}, ${dns2}]
EOF

    # Set permission yang benar
    chown root:root /etc/netplan/00-installer-config.yaml
    chmod 0600 /etc/netplan/00-installer-config.yaml

    # Generate dan terapkan konfigurasi
    netplan generate

    # Terapkan konfigurasi dengan penanganan error
    if ! netplan apply; then
        warning_msg "Mencoba menerapkan konfigurasi dalam mode debug..."
        netplan --debug apply
    fi

    # Tunggu sebentar untuk interface up
    sleep 5

    # Verifikasi koneksi
    if ping -c 1 ${gateway} > /dev/null 2>&1; then
        success_msg "Konfigurasi IP statis berhasil diterapkan"
        return 0
    else
        error_exit "Gagal menerapkan konfigurasi IP statis"
        if [ -f "/etc/netplan/00-installer-config.yaml.backup" ]; then
            mv /etc/netplan/00-installer-config.yaml.backup /etc/netplan/00-installer-config.yaml
            chmod 0600 /etc/netplan/00-installer-config.yaml
            netplan apply
        fi
        return 1
    fi
}

# Fungsi untuk memeriksa persyaratan sistem Wazuh
check_wazuh_system_requirements() {
    info_msg "Memeriksa persyaratan sistem untuk Wazuh..."
    
    # Periksa RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 4096 ]; then
        warning_msg "RAM kurang dari 4GB. Wazuh membutuhkan minimal 4GB RAM"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Periksa disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        warning_msg "Ruang disk kurang dari 20GB. Wazuh membutuhkan minimal 20GB free space"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Fungsi untuk menangani error Wazuh
handle_wazuh_error() {
    local error_msg="$1"
    error_exit "Wazuh Error: $error_msg"
}

# Fungsi untuk generate perintah instalasi agent Wazuh
generate_wazuh_agent_command() {
    local server_ip=$1
    local WAZUH_VERSION="4.7.5"
    local ARCHITECTURE="amd64"

    info_msg "Membuat generator perintah instalasi Wazuh Agent"
    echo "IP Server Wazuh: $server_ip"

    # Input nama agent
    echo "Masukkan nomor atau nama untuk agent (default: ubuntu-agent):"
    read agent_name
    if [ -z "$agent_name" ]; then
        agent_name="ubuntu-agent"
    fi

    # Generate perintah instalasi
    local install_command="wget https://packages.wazuh.com/${WAZUH_VERSION%.*}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb && sudo WAZUH_MANAGER='${server_ip}' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='${agent_name}' dpkg -i ./wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb"

    # Simpan perintah ke file
    cat > /root/install_wazuh_agent.sh << EOF
#!/bin/bash

# Script instalasi Wazuh Agent
# Generated pada: $(date)
# Server: $server_ip
# Agent Name: $agent_name

$install_command

# Start Wazuh Agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Check status
sudo systemctl status wazuh-agent
EOF

    chmod +x /root/install_wazuh_agent.sh

    success_msg "Script instalasi agent telah dibuat: /root/install_wazuh_agent.sh"
    echo "Perintah instalasi untuk agent:"
    echo "$install_command"
    echo "Atau gunakan script yang telah dibuat:"
    echo "scp /root/install_wazuh_agent.sh user@agent-ip:~/"
    echo "ssh user@agent-ip 'sudo bash ~/install_wazuh_agent.sh'"

    # Tampilkan ringkasan
    echo "Ringkasan Agent Installation:"
    echo "1. Server IP: $server_ip"
    echo "2. Agent Name: $agent_name"
    echo "3. Wazuh Version: $WAZUH_VERSION"
    echo "4. Architecture: $ARCHITECTURE"
    echo "5. Agent Group: default"
}

# Fungsi untuk instalasi Wazuh
install_wazuh() {
    info_msg "Memulai instalasi Wazuh..."
    
    # Deteksi otomatis konfigurasi jaringan
    info_msg "Mendeteksi konfigurasi jaringan..."

    # Deteksi interface utama
    INTERFACE=$(get_main_interface)
    success_msg "Interface terdeteksi: $INTERFACE"

    # Deteksi gateway
    GATEWAY=$(get_default_gateway)
    if [ -z "$GATEWAY" ]; then
        warning_msg "Tidak dapat mendeteksi gateway. Menggunakan default gateway"
        GATEWAY="192.168.1.1"
    fi
    success_msg "Gateway terdeteksi: $GATEWAY"

    # Set IP statis yang tersedia
    STATIC_IP=$(get_available_ip "$INTERFACE" "$GATEWAY")
    success_msg "IP statis yang akan digunakan: $STATIC_IP"

    # Set konfigurasi default
    NETMASK="24"
    DNS1="8.8.8.8"
    DNS2="8.8.4.4"

    # Periksa persyaratan sistem
    check_wazuh_system_requirements

    # Terapkan konfigurasi IP statis
    info_msg "Menerapkan konfigurasi IP statis..."
    configure_static_ip "$STATIC_IP" "$INTERFACE" "$NETMASK" "$GATEWAY" "$DNS1" "$DNS2"

    # Buat direktori untuk menyimpan file instalasi
    INSTALL_DIR="/root/wazuh-install-files"
    mkdir -p ${INSTALL_DIR}
    cd ${INSTALL_DIR}

    # Download Wazuh installer
    info_msg "Mengunduh Wazuh installer..."
    if ! curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh; then
        handle_wazuh_error "Gagal mengunduh installer Wazuh"
    fi

    chmod +x wazuh-install.sh

    # Membuat config.yml
    cat > config.yml << EOF
nodes:
  indexer:
    - name: node-1
      ip: ${STATIC_IP}
      role: master
  server:
    - name: wazuh-1
      ip: ${STATIC_IP}
  dashboard:
    - name: dashboard
      ip: ${STATIC_IP}
EOF

    # Buat direktori untuk menyimpan kredensial
    CRED_DIR="/root/wazuh-credentials"
    mkdir -p ${CRED_DIR}
    chmod 700 ${CRED_DIR}

    # Menjalankan instalasi dengan penanganan error
    success_msg "Memulai instalasi Wazuh..."

    # Generate config files
    if ! ./wazuh-install.sh --generate-config-files; then
        handle_wazuh_error "Gagal generate config files"
    fi
    success_msg "Konfigurasi berhasil di-generate"

    # Install dan start Wazuh indexer
    if ! ./wazuh-install.sh --wazuh-indexer node-1; then
        handle_wazuh_error "Gagal instalasi wazuh indexer"
    fi
    success_msg "Wazuh indexer berhasil diinstal"

    # Tunggu indexer siap
    info_msg "Menunggu Wazuh indexer siap..."
    sleep 30

    # Start cluster
    if ! ./wazuh-install.sh --start-cluster; then
        handle_wazuh_error "Gagal memulai cluster"
    fi
    success_msg "Cluster berhasil dimulai"

    # Simpan password
    info_msg "Menyimpan kredensial..."
    tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > ${CRED_DIR}/wazuh-passwords-full.txt
    chmod 600 ${CRED_DIR}/wazuh-passwords-full.txt

    # Install Wazuh server
    if ! ./wazuh-install.sh --wazuh-server wazuh-1; then
        handle_wazuh_error "Gagal instalasi wazuh server"
    fi
    success_msg "Wazuh server berhasil diinstal"

    # Tunggu server siap
    info_msg "Menunggu Wazuh server siap..."
    sleep 30

    # Install Wazuh dashboard
    if ! ./wazuh-install.sh --wazuh-dashboard dashboard; then
        handle_wazuh_error "Gagal instalasi wazuh dashboard"
    fi
    success_msg "Wazuh dashboard berhasil diinstal"

    # Ekstrak dan simpan password spesifik
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "admin" > ${CRED_DIR}/admin-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "wazuh" > ${CRED_DIR}/wazuh-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "kibana" > ${CRED_DIR}/kibana-passwords.txt

    # Buat file rangkuman kredensial
    cat > ${CRED_DIR}/credentials-summary.txt << EOF
Wazuh Credentials Summary
========================
Tanggal Instalasi: $(date)
IP Server: ${STATIC_IP}

Lokasi File Kredensial:
- Password Lengkap: ${CRED_DIR}/wazuh-passwords-full.txt
- Password Admin: ${CRED_DIR}/admin-passwords.txt
- Password Wazuh: ${CRED_DIR}/wazuh-passwords.txt
- Password Kibana: ${CRED_DIR}/kibana-passwords.txt

Akses Dashboard: https://${STATIC_IP}
Default username: admin

Note: 
- Simpan file ini di tempat yang aman
- Ganti password default setelah login pertama
- Backup folder ${CRED_DIR} secara berkala
EOF

    # Set permission untuk file kredensial
    chmod 600 ${CRED_DIR}/*
    chown -R root:root ${CRED_DIR}

    # Tambahkan entri ke /etc/hosts
    echo "${STATIC_IP} node-1 wazuh-1 dashboard" >> /etc/hosts

    # Periksa status layanan
    info_msg "Memeriksa status layanan..."
    services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            success_msg "Service $service berjalan dengan baik"
        else
            warning_msg "Service $service tidak berjalan"
            systemctl status $service
            info_msg "Mencoba restart service ${service}..."
            systemctl restart $service
            sleep 5
            if systemctl is-active --quiet $service; then
                success_msg "Service $service berhasil direstart"
            else
                warning_msg "Service $service masih bermasalah"
            fi
        fi
    done

    # Simpan informasi konfigurasi
    cat > /root/wazuh-info.txt << EOF
Konfigurasi Wazuh:
=================
IP Address: ${STATIC_IP}
Interface: ${INTERFACE}
Netmask: ${NETMASK}
Gateway: ${GATEWAY}
DNS1: ${DNS1}
DNS2: ${DNS2}

Dashboard URL: https://${STATIC_IP}

Lokasi File Kredensial: ${CRED_DIR}
EOF

    success_msg "Instalasi Wazuh selesai!"
    echo "Anda dapat mengakses dashboard di: https://${STATIC_IP}"
    echo "Kredensial tersimpan di: ${CRED_DIR}"
    echo "Informasi konfigurasi tersimpan di: /root/wazuh-info.txt"

    # Generate script instalasi agent
    info_msg "Membuat script instalasi untuk Wazuh Agent..."
    generate_wazuh_agent_command "${STATIC_IP}"

    success_msg "Proses instalasi dan konfigurasi Wazuh selesai!"
    
    # Return ke direktori asal
    cd "$SCRIPT_DIR"
}

# ==============================================================================
# FUNGSI INSTALASI MISP
# ==============================================================================

# Function to check MISP dependencies
check_misp_dependencies() {
    info_msg "Checking MISP dependencies..."
    if ! command -v docker &> /dev/null; then
        error_exit "Error: 'docker' is not installed. Please install Docker first."
    fi
    if ! command -v docker-compose &> /dev/null; then
        error_exit "Error: 'docker-compose' is not installed. Please install Docker Compose first."
    fi
    success_msg "MISP dependencies are satisfied."
}

# Function to wait for MISP to become available
wait_for_misp() {
    info_msg "Waiting for MISP to become available... This may take several minutes."
    until curl --output /dev/null --silent --head --fail --insecure https://localhost; do
        printf '.'
        sleep 5
    done
    success_msg "MISP is up and running!"
}

# Function to install and setup MISP
install_misp() {
    info_msg "Memulai instalasi MISP..."
    
    # MISP Configuration
    MISP_INSTALL_DIR="/opt/misp-docker"
    MISP_DOCKER_COMPOSE_URL="https://raw.githubusercontent.com/misp/misp-docker/main/docker-compose.yml"
    
    # Detail untuk pengguna API yang akan dibuat
    ORG_NAME="Wazuh-IR-Automation"
    USER_EMAIL_FOR_KEY="wazuh-automation@localhost.local"
    USER_COMMENT="API key for Wazuh Active Response integration"
    
    check_misp_dependencies
    
    # Periksa apakah kontainer MISP sudah berjalan
    MISP_CONTAINER_ID=$(docker ps -q --filter "name=misp-server")
    
    if [ -z "$MISP_CONTAINER_ID" ]; then
        info_msg "MISP container not found. Starting installation process..."
        
        # 1. Buat direktori instalasi
        info_msg "Creating installation directory at ${MISP_INSTALL_DIR}..."
        run_command "mkdir -p '$MISP_INSTALL_DIR'" "Creating MISP installation directory"
        cd "$MISP_INSTALL_DIR"
        
        # 2. Unduh file docker-compose.yml
        info_msg "Downloading latest misp-docker docker-compose.yml..."
        run_command "curl -o docker-compose.yml '$MISP_DOCKER_COMPOSE_URL'" "Downloading MISP docker-compose file"
        
        # 3. Jalankan MISP menggunakan docker-compose
        info_msg "Starting MISP containers in detached mode (-d)..."
        run_command "docker-compose up -d" "Starting MISP containers"
        
        # 4. Tunggu hingga MISP benar-benar siap
        wait_for_misp
        
        success_msg "MISP installation completed successfully."
    else
        success_msg "MISP is already installed and running."
        # Pastikan kita berada di direktori yang benar untuk perintah exec
        cd "$MISP_INSTALL_DIR"
    fi
    
    # Pengambilan API Key
    info_msg "Attempting to create/retrieve API key for user '${USER_EMAIL_FOR_KEY}'..."
    
    # Dapatkan email admin default dari dalam kontainer
    ADMIN_EMAIL=$(docker-compose exec -T misp-server cat /var/www/MISP/app/Config/config.php | grep "'email' =>" | head -1 | sed "s/.*'email' => '\([^']*\)'.*/\1/")
    
    if [ -z "$ADMIN_EMAIL" ]; then
        warning_msg "Could not automatically determine admin email. Defaulting to 'admin@admin.test'."
        ADMIN_EMAIL="admin@admin.test"
    fi
    
    info_msg "Using admin email: ${ADMIN_EMAIL}"
    
    # Gunakan perintah 'cake' di dalam kontainer untuk membuat pengguna dan mendapatkan kuncinya
    API_KEY_OUTPUT=$(docker-compose exec -T misp-server \
        /var/www/MISP/app/Console/cake Admin setApiUser "$ADMIN_EMAIL" "$ORG_NAME" "$USER_EMAIL_FOR_KEY" "$USER_COMMENT")
    
    # Ekstrak kunci API dari output
    MISP_KEY=$(echo "$API_KEY_OUTPUT" | grep 'Auth key:' | awk '{print $3}')
    
    if [ -n "$MISP_KEY" ]; then
        success_msg "Successfully retrieved API Key!"
        echo "------------------------------------------------------------------"
        echo "Your MISP API Key is: $MISP_KEY"
        echo "------------------------------------------------------------------"
        echo "Simpan kunci ini di tempat yang aman. Anda akan membutuhkannya untuk"
        echo "mengkonfigurasi skrip integrasi Wazuh."
        
        # Update config.conf dengan API key yang baru
        if [ -f "/etc/soc-config/config.conf" ]; then
            sed -i "s/MISP_KEY=.*/MISP_KEY=\"$MISP_KEY\"/" /etc/soc-config/config.conf
            success_msg "MISP API Key berhasil diupdate di config.conf"
        fi
    else
        error_exit "Error: Failed to retrieve API Key."
        info_msg "Please check the logs using 'docker-compose logs -f' in '${MISP_INSTALL_DIR}'."
    fi
    
    success_msg "MISP setup completed successfully!"
}

# ==============================================================================
# FUNGSI INSTALASI SERVER MONITORING
# ==============================================================================

# Function to setup monitoring server (backup repository)
install_monitoring_server() {
    info_msg "Memulai instalasi Server Monitoring (Backup Repository)..."
    
    # Tentukan direktori untuk menyimpan backup
    info_msg "Menentukan direktori untuk menyimpan backup Git dan arsip dinamis..."
    read -r -p "Masukkan path direktori utama backup (default: /var/backup/web_backups): " MAIN_BACKUP_DIR
    MAIN_BACKUP_DIR=${MAIN_BACKUP_DIR:-/var/backup/web_backups}

    # Path untuk backup Git (repositori bare)
    GIT_BACKUP_SUBDIR="git_repo" # Nama subdirektori untuk Git
    ACTUAL_GIT_BACKUP_PATH="$MAIN_BACKUP_DIR/$GIT_BACKUP_SUBDIR"

    # Path untuk backup file dinamis (arsip .tar.gz)
    DYNAMIC_BACKUP_SUBDIR="dynamic_archives" # Nama subdirektori untuk arsip dinamis
    ACTUAL_DYNAMIC_BACKUP_PATH="$MAIN_BACKUP_DIR/$DYNAMIC_BACKUP_SUBDIR"

    # Buat direktori backup jika belum ada
    if [ ! -d "$ACTUAL_GIT_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup Git: $ACTUAL_GIT_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_GIT_BACKUP_PATH'" "Creating Git backup directory"
    fi
    if [ ! -d "$ACTUAL_DYNAMIC_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup dinamis: $ACTUAL_DYNAMIC_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_DYNAMIC_BACKUP_PATH'" "Creating dynamic backup directory"
    fi

    # Membuat pengguna khusus untuk backup
    echo ""
    info_msg "Pengaturan Pengguna Khusus untuk Menerima Backup"
    echo "----------------------------------------------------"
    read -r -p "Apakah Anda ingin membuat pengguna sistem khusus untuk menerima backup via SSH? (y/n, default: y): " CREATE_USER
    CREATE_USER=${CREATE_USER:-y}

    BACKUP_USER="" # Akan diisi jika CREATE_USER=y

    if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]]; then
        read -r -p "Masukkan nama pengguna untuk backup (default: webbackupuser): " INPUT_BACKUP_USER
        BACKUP_USER=${INPUT_BACKUP_USER:-webbackupuser}
        
        if id "$BACKUP_USER" &>/dev/null; then
            info_msg "Pengguna '$BACKUP_USER' sudah ada."
        else
            info_msg "Membuat pengguna '$BACKUP_USER'..."
            run_command "useradd -r -m -s /bin/bash '$BACKUP_USER'" "Creating backup user"
            success_msg "Pengguna '$BACKUP_USER' berhasil dibuat."
        fi
        
        info_msg "Mengatur kepemilikan direktori backup untuk pengguna '$BACKUP_USER'..."
        run_command "chown -R '$BACKUP_USER:$BACKUP_USER' '$MAIN_BACKUP_DIR'" "Setting ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting permissions of backup directory"

        # Inisialisasi repository Git bare
        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH'..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
            read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        
        # Mengatur SSH untuk pengguna backup
        USER_SSH_DIR="/home/$BACKUP_USER/.ssh"
        info_msg "Memastikan direktori SSH '$USER_SSH_DIR' dan 'authorized_keys' ada untuk pengguna '$BACKUP_USER'..."
        run_command "sudo -u '$BACKUP_USER' mkdir -p '$USER_SSH_DIR'" "Creating SSH directory for backup user"
        run_command "sudo -u '$BACKUP_USER' touch '$USER_SSH_DIR/authorized_keys'" "Creating authorized_keys file"
        run_command "sudo -u '$BACKUP_USER' chmod 700 '$USER_SSH_DIR'" "Setting SSH directory permissions"
        run_command "sudo -u '$BACKUP_USER' chmod 600 '$USER_SSH_DIR/authorized_keys'" "Setting authorized_keys permissions"
        success_msg "Setup direktori SSH untuk '$BACKUP_USER' selesai."
        
        echo ""
        info_msg "--- INSTRUKSI PENTING UNTUK SERVER WEB ---"
        echo "Untuk mengizinkan server web melakukan push backup ke server monitoring ini:"
        echo "1. Di SERVER WEB, pastikan Anda memiliki SSH key pair untuk user root (atau user yang menjalankan backup)."
        echo "   Kunci publiknya (biasanya di '/root/.ssh/id_rsa_web_backup.pub') perlu disalin."
        echo "2. Di SERVER MONITORING INI, tambahkan isi kunci publik tersebut ke dalam file:"
        echo "   $USER_SSH_DIR/authorized_keys"
        echo "3. Pastikan pengguna '$BACKUP_USER' adalah pemilik file tersebut dan memiliki izin yang benar (chmod 600)."
        echo "--------------------------------------------"

    else # Jika tidak membuat pengguna khusus, backup akan diterima oleh root
        BACKUP_USER="root" # Backup akan menggunakan root jika tidak ada user khusus
        warning_msg "PERINGATAN: Tidak ada pengguna khusus yang dibuat. Backup akan diterima sebagai pengguna 'root'. Ini kurang aman."
        info_msg "Pastikan direktori '$MAIN_BACKUP_DIR' dapat ditulis oleh root."
        run_command "chown -R 'root:root' '$MAIN_BACKUP_DIR'" "Setting root ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting root permissions of backup directory"

        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH' sebagai root..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
             read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository as root"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository as root"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        info_msg "SSH key dari server web perlu ditambahkan ke '/root/.ssh/authorized_keys' di server monitoring ini."
    fi

    # Konfigurasi Monitoring Server Ini Sendiri (Opsional)
    echo ""
    info_msg "Konfigurasi Monitoring untuk Server Backup Ini Sendiri (Opsional)"
    echo "-------------------------------------------------------------------"
    read -r -p "Apakah Anda ingin menginstal Wazuh Agent untuk memonitor server backup ini sendiri? (y/n, default: n): " INSTALL_WAZUH_AGENT_LOCAL
    INSTALL_WAZUH_AGENT_LOCAL=${INSTALL_WAZUH_AGENT_LOCAL:-n}

    if [[ "$INSTALL_WAZUH_AGENT_LOCAL" == "y" || "$INSTALL_WAZUH_AGENT_LOCAL" == "Y" ]]; then
        info_msg "Memulai instalasi Wazuh Agent untuk server backup ini..."
        
        if ! command -v apt-key &> /dev/null || ! command -v tee &> /dev/null ; then
            run_command "apt-get install -y gnupg apt-transport-https" "Installing gnupg and apt-transport-https"
        fi

        run_command "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg" "Importing Wazuh GPG key"
        run_command "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list" "Adding Wazuh repository"
        
        run_command "apt-get update -y" "Updating package list after adding Wazuh repository"
        run_command "apt-get install -y wazuh-agent" "Installing Wazuh Agent"
        
        read -r -p "Masukkan alamat IP Wazuh Manager untuk agent ini: " WAZUH_MANAGER_IP_FOR_AGENT
        while [[ -z "$WAZUH_MANAGER_IP_FOR_AGENT" ]]; do
            read -r -p "Alamat IP Wazuh Manager tidak boleh kosong. Masukkan IP: " WAZUH_MANAGER_IP_FOR_AGENT
        done
        
        # Konfigurasi Wazuh Agent (ossec.conf)
        run_command "sed -i 's|<address>MANAGER_IP</address>|<address>$WAZUH_MANAGER_IP_FOR_AGENT</address>|g' /var/ossec/etc/ossec.conf" "Configuring Wazuh Agent manager IP"
        
        run_command "systemctl daemon-reload" "Reloading systemd daemon"
        run_command "systemctl enable wazuh-agent" "Enabling Wazuh Agent service"
        run_command "systemctl restart wazuh-agent" "Starting Wazuh Agent service"
        
        success_msg "Wazuh Agent berhasil diinstal dan dikonfigurasi untuk memonitor server backup ini."
        info_msg "Pastikan untuk mendaftarkan agent ini di Wazuh Manager."
    else
        info_msg "Instalasi Wazuh Agent untuk server backup ini dilewati."
    fi

    # Konfigurasi Git Hooks untuk Notifikasi (opsional)
    echo ""
    info_msg "Konfigurasi Git Hook untuk Notifikasi Email (Opsional)"
    echo "---------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur notifikasi email setiap kali backup Git diterima? (y/n, default: n): " SETUP_NOTIFICATION
    SETUP_NOTIFICATION=${SETUP_NOTIFICATION:-n}

    if [[ "$SETUP_NOTIFICATION" == "y" || "$SETUP_NOTIFICATION" == "Y" ]]; then
        if ! command -v mail &> /dev/null; then
            info_msg "Command 'mail' (mailutils) tidak ditemukan. Menginstal..."
            run_command "apt-get install -y mailutils" "Installing mailutils for email notifications"
        fi

        if command -v mail &> /dev/null; then
            read -r -p "Masukkan alamat email untuk notifikasi: " NOTIFY_EMAIL
            while [[ -z "$NOTIFY_EMAIL" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " NOTIFY_EMAIL
            done
            
            HOOK_DIR="$ACTUAL_GIT_BACKUP_PATH/hooks"
            HOOK_FILE="$HOOK_DIR/post-receive"

            info_msg "Membuat direktori hook $HOOK_DIR jika belum ada..."
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "sudo -u '$BACKUP_USER' mkdir -p '$HOOK_DIR'" "Creating hook directory as backup user"
            else
                run_command "mkdir -p '$HOOK_DIR'" "Creating hook directory"
            fi

            info_msg "Membuat skrip post-receive hook di $HOOK_FILE..."
            cat > "$HOOK_FILE" << EOF_HOOK
#!/bin/bash
# Git hook untuk mengirim notifikasi email saat menerima backup baru

REPO_NAME="\$(basename "\$(pwd)")"
COMMIT_INFO=\$(git log -1 --pretty=format:"%h - %an, %ar : %s")
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=\$(date +"%Y-%m-%d %H:%M:%S")

mail -s "Backup GIT Baru Diterima di \$SERVER_HOSTNAME untuk \$REPO_NAME" "$NOTIFY_EMAIL" << EOM_MAIL
Backup Git baru telah diterima di server monitoring: \$SERVER_HOSTNAME

Repository Path: \$(pwd)
Timestamp: \$TIMESTAMP
Commit Terakhir: \$COMMIT_INFO

Pesan ini dikirim otomatis dari hook post-receive.
EOM_MAIL
EOF_HOOK

            run_command "chmod +x '$HOOK_FILE'" "Making hook file executable"
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "chown '$BACKUP_USER:$BACKUP_USER' '$HOOK_FILE'" "Setting hook file ownership to backup user"
                info_msg "Kepemilikan hook diatur ke $BACKUP_USER."
            fi
            success_msg "Notifikasi email untuk backup Git baru telah dikonfigurasi di $HOOK_FILE."
            info_msg "Pastikan MTA (seperti Postfix atau ssmtp) terkonfigurasi di server ini agar perintah 'mail' berfungsi."
        else
            warning_msg "Gagal menginstal atau menemukan 'mail'. Notifikasi email dilewati."
        fi
    fi

    # Monitoring disk space untuk MAIN_BACKUP_DIR (opsional)
    echo ""
    info_msg "Monitoring Disk Space untuk Direktori Backup (Opsional)"
    echo "-----------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur monitoring disk space untuk '$MAIN_BACKUP_DIR'? (y/n, default: y): " SETUP_DISK_MONITORING
    SETUP_DISK_MONITORING=${SETUP_DISK_MONITORING:-y}

    if [[ "$SETUP_DISK_MONITORING" == "y" || "$SETUP_DISK_MONITORING" == "Y" ]]; then
        if ! command -v mail &> /dev/null && ! command -v mailx &> /dev/null ; then
            info_msg "Command 'mail' atau 'mailx' tidak ditemukan. Menginstal mailutils..."
            run_command "apt-get install -y mailutils" "Installing mailutils for disk monitoring"
        fi

        if command -v mail &> /dev/null || command -v mailx &> /dev/null ; then
            MONITOR_SCRIPT_PATH="/usr/local/bin/monitor_backup_disk_space.sh"
            info_msg "Membuat skrip monitoring disk di $MONITOR_SCRIPT_PATH..."

            cat > "$MONITOR_SCRIPT_PATH" << EOF_DISK_MON
#!/bin/bash
# Skrip untuk memonitor penggunaan disk direktori backup

TARGET_BACKUP_DIR="\$1"
USAGE_THRESHOLD="\$2" # Persentase, misal 80
EMAIL_RECIPIENT="\$3"
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
LOG_FILE="/var/log/backup_disk_monitor.log"
MAIL_COMMAND=\$(command -v mail || command -v mailx)

if [ -z "\$MAIL_COMMAND" ]; then
    echo "[\$(date)] Error: Perintah mail/mailx tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

if [ ! -d "\$TARGET_BACKUP_DIR" ]; then
    echo "[\$(date)] Error: Direktori backup '\$TARGET_BACKUP_DIR' tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

CURRENT_USAGE=\$(df "\$TARGET_BACKUP_DIR" | awk 'NR==2 {print \$5}' | sed 's/%//')

if [ -z "\$CURRENT_USAGE" ]; then
    echo "[\$(date)] Error: Tidak dapat mengambil info penggunaan disk untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
    exit 1
fi

if [ "\$CURRENT_USAGE" -gt "\$USAGE_THRESHOLD" ]; then
    SUBJECT="[PERINGATAN] Disk Backup di \$SERVER_HOSTNAME Hampir Penuh (\$CURRENT_USAGE%)"
    MESSAGE="Penggunaan disk pada direktori backup '\$TARGET_BACKUP_DIR' di server \$SERVER_HOSTNAME telah mencapai \$CURRENT_USAGE% (Threshold: \$USAGE_THRESHOLD%).\n\nDetail Penggunaan Disk:\n\$(df -h "\$TARGET_BACKUP_DIR")\n\nHarap segera periksa dan kosongkan ruang jika perlu."
    
    echo -e "\$MESSAGE" | \$MAIL_COMMAND -s "\$SUBJECT" "\$EMAIL_RECIPIENT"
    echo "[\$(date)] Peringatan Terkirim: Penggunaan disk \$CURRENT_USAGE% melebihi threshold \$USAGE_THRESHOLD% untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
else
    echo "[\$(date)] Info: Penggunaan disk \$CURRENT_USAGE% untuk '\$TARGET_BACKUP_DIR' masih di bawah threshold \$USAGE_THRESHOLD%." >> "\$LOG_FILE"
fi
exit 0
EOF_DISK_MON
            run_command "chmod +x '$MONITOR_SCRIPT_PATH'" "Making disk monitoring script executable"
            success_msg "Skrip monitoring disk $MONITOR_SCRIPT_PATH berhasil dibuat."

            read -r -p "Masukkan threshold penggunaan disk dalam persen (misal 80, default: 80): " DISK_THRESHOLD_INPUT
            DISK_THRESHOLD_INPUT=${DISK_THRESHOLD_INPUT:-80}
            read -r -p "Masukkan alamat email untuk notifikasi disk space: " DISK_EMAIL_INPUT
            while [[ -z "$DISK_EMAIL_INPUT" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " DISK_EMAIL_INPUT
            done
            
            CRON_DISK_MON_ENTRY="0 7 * * * $MONITOR_SCRIPT_PATH \"$MAIN_BACKUP_DIR\" \"$DISK_THRESHOLD_INPUT\" \"$DISK_EMAIL_INPUT\""
            
            # Tambahkan ke crontab root
            run_command "(crontab -l 2>/dev/null | grep -vF '$MONITOR_SCRIPT_PATH'; echo '$CRON_DISK_MON_ENTRY') | crontab -" "Adding disk monitoring to crontab"
            success_msg "Monitoring disk space untuk direktori backup '$MAIN_BACKUP_DIR' telah diatur via cron."
            info_msg "Log monitoring disk akan ada di /var/log/backup_disk_monitor.log"
        else
            warning_msg "Gagal menginstal atau menemukan 'mail/mailx'. Monitoring disk space dilewati."
        fi
    fi

    SERVER_IP_ADDRESS=$(hostname -I | awk '{print $1}') # Ambil IP utama

    echo ""
    echo "================================================================="
    echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
    echo "================================================================="
    echo ""
    echo "Informasi Penting untuk Konfigurasi Server Web:"
    echo "----------------------------------------------"
    echo "IP Server Monitoring Ini: ${SERVER_IP_ADDRESS:-Mohon periksa manual}"
    echo "Pengguna SSH untuk Backup: $BACKUP_USER"
    echo "Path Tujuan Backup Git: $ACTUAL_GIT_BACKUP_PATH"
    echo "Path Tujuan Backup Dinamis (arsip): $ACTUAL_DYNAMIC_BACKUP_PATH"
    echo ""
    echo "Contoh Perintah di Server Web untuk Menambahkan Remote Git:"
    echo "   git remote add monitoring $BACKUP_USER@${SERVER_IP_ADDRESS:-<IP_SERVER_MONITORING>}:$ACTUAL_GIT_BACKUP_PATH"
    echo ""
    echo "CATATAN PENTING:"
    echo "- Format URL Git SSH yang disarankan: '$BACKUP_USER@<IP_SERVER_MONITORING>:$ACTUAL_GIT_BACKUP_PATH' (gunakan path absolut)."
    echo "- Pastikan kunci SSH publik dari server web (user root atau yang menjalankan backup) telah ditambahkan ke:"
    echo "  '/home/$BACKUP_USER/.ssh/authorized_keys' (jika $BACKUP_USER dibuat) atau '/root/.ssh/authorized_keys' (jika tidak ada user khusus) di server monitoring ini."
    echo "- Pastikan direktori '$ACTUAL_DYNAMIC_BACKUP_PATH' dapat ditulis oleh '$BACKUP_USER' (atau root) melalui rsync/scp."
    echo ""
    echo "Server monitoring ini sekarang siap menerima backup."
    echo "================================================================="
}

# ==============================================================================
# FUNGSI KONFIGURASI SOC
# ==============================================================================

# Function to collect user input for configuration
collect_user_config() {
    info_msg "Mengumpulkan konfigurasi dari user..."
    
    # Web directory
    read -r -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
    WEB_DIR=${WEB_DIR:-/var/www/html}
    
    # Backup directory
    read -r -p "Masukkan path direktori backup (default: /var/soc-backup): " BACKUP_DIR
    BACKUP_DIR=${BACKUP_DIR:-/var/soc-backup}
    
    # Quarantine directory
    read -r -p "Masukkan path direktori karantina (default: /var/soc-quarantine): " QUARANTINE_DIR
    QUARANTINE_DIR=${QUARANTINE_DIR:-/var/soc-quarantine}
    
    # Log directory
    read -r -p "Masukkan path direktori log (default: /var/log/soc-incident-response): " LOG_DIR
    LOG_DIR=${LOG_DIR:-/var/log/soc-incident-response}
    
    # Wazuh alerts file
    read -r -p "Masukkan path file alerts Wazuh (default: /var/ossec/logs/alerts/alerts.json): " WAZUH_ALERTS_FILE
    WAZUH_ALERTS_FILE=${WAZUH_ALERTS_FILE:-/var/ossec/logs/alerts/alerts.json}
    
    # Rule IDs
    read -r -p "Masukkan Rule IDs untuk defacement (default: 550,554,5501,5502,5503,5504,100001,100002): " DEFACE_RULE_IDS
    DEFACE_RULE_IDS=${DEFACE_RULE_IDS:-550,554,5501,5502,5503,5504,100001,100002}
    
    read -r -p "Masukkan Rule IDs untuk serangan (default: 5710,5712,5715,5760,100003,100004): " ATTACK_RULE_IDS
    ATTACK_RULE_IDS=${ATTACK_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk eradication (default: 5710,5712,5715,5760,100003,100004): " ERADICATION_RULE_IDS
    ERADICATION_RULE_IDS=${ERADICATION_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk restore (default: 100010,100011,100012): " RESTORE_RULE_IDS
    RESTORE_RULE_IDS=${RESTORE_RULE_IDS:-100010,100011,100012}
    
    # MISP Configuration
    read -r -p "Masukkan URL MISP (default: https://192.168.28.135): " MISP_URL
    MISP_URL=${MISP_URL:-https://192.168.28.135}
    
    read -r -p "Masukkan API Key MISP: " MISP_KEY
    if [[ -z "$MISP_KEY" ]]; then
        MISP_KEY="XweOnEWOtWFmIbW585H2m03R3SIZRmIKxrza73WB"
        warning_msg "Menggunakan API Key default MISP"
    fi
    
    read -r -p "Verifikasi sertifikat MISP? (y/n, default: n): " MISP_VERIFY_CERT
    if [[ "$MISP_VERIFY_CERT" =~ ^[Yy]$ ]]; then
        MISP_VERIFY_CERT="true"
    else
        MISP_VERIFY_CERT="false"
    fi
    
    # Monitoring server
    while true; do
        read -r -p "Masukkan IP server monitoring (default: 192.168.1.100): " MONITORING_SERVER
        MONITORING_SERVER=${MONITORING_SERVER:-192.168.1.100}
        if validate_ip "$MONITORING_SERVER"; then
            break
        else
            warning_msg "IP address tidak valid. Silakan coba lagi."
        fi
    done
    
    read -r -p "Masukkan username server monitoring (default: soc-backup): " MONITORING_USER
    MONITORING_USER=${MONITORING_USER:-soc-backup}
    
    read -s -p "Masukkan password server monitoring: " MONITORING_PASSWORD
    echo
    
    # Backup paths
    read -r -p "Masukkan path backup remote (default: /home/soc-backup/backups): " REMOTE_BACKUP_PATH
    REMOTE_BACKUP_PATH=${REMOTE_BACKUP_PATH:-/home/soc-backup/backups}
    
    # Web server user/group
    read -r -p "Masukkan user web server (default: www-data): " WEB_SERVER_USER
    WEB_SERVER_USER=${WEB_SERVER_USER:-www-data}
    
    read -r -p "Masukkan group web server (default: www-data): " WEB_SERVER_GROUP
    WEB_SERVER_GROUP=${WEB_SERVER_GROUP:-www-data}
    
    # Password untuk restore
    read -s -p "Masukkan password untuk restore (minimal 12 karakter): " RESTORE_PASSWORD
    echo
    if [[ ${#RESTORE_PASSWORD} -lt 12 ]]; then
        error_exit "Password harus minimal 12 karakter"
    fi
    ENCODED_PASSWORD=$(echo -n "$RESTORE_PASSWORD" | base64)
    
    success_msg "Konfigurasi user berhasil dikumpulkan"
}

# Function to create config.conf from user input
create_config_file() {
    info_msg "Membuat file config.conf..."
    
    local config_dir="/etc/soc-config"
    run_command "mkdir -p '$config_dir'" "Creating SOC config directory"
    
    cat > "$config_dir/config.conf" << EOF
# =================================================================
# SOC INCIDENT RESPONSE CONFIGURATION - NIST 800-61r2 FRAMEWORK
# =================================================================
# File konfigurasi terpusat untuk semua script IRLC
# Sesuai dengan NIST 800-61r2: Preparation, Detection & Analysis, 
# Containment, Eradication, Recovery, dan Post-Incident Activity

# =================================================================
# PREPARATION PHASE - Konfigurasi Dasar Sistem
# =================================================================

# Direktori web yang akan diproteksi
WEB_DIR="$WEB_DIR"

# Direktori backup utama
BACKUP_DIR="$BACKUP_DIR"

# Direktori karantina untuk file mencurigakan
QUARANTINE_DIR="$QUARANTINE_DIR"

# Direktori log untuk semua aktivitas IRLC
LOG_DIR="$LOG_DIR"

# Direktori konfigurasi SOC
SOC_CONFIG_DIR="$config_dir"

# =================================================================
# DETECTION & ANALYSIS PHASE - Wazuh Integration
# =================================================================

# File alerts.json utama Wazuh
WAZUH_ALERTS_FILE="$WAZUH_ALERTS_FILE"

# Direktori log Wazuh active response
WAZUH_ACTIVE_RESPONSE_LOG_DIR="/var/log/wazuh/active-response"

# Rule IDs untuk deteksi defacement
DEFACE_RULE_IDS="$DEFACE_RULE_IDS"

# Rule IDs untuk deteksi serangan
ATTACK_RULE_IDS="$ATTACK_RULE_IDS"

# Rule IDs untuk trigger eradication
ERADICATION_RULE_IDS="$ERADICATION_RULE_IDS"

# Rule IDs untuk trigger auto restore
RESTORE_RULE_IDS="$RESTORE_RULE_IDS"

# =================================================================
# CONTAINMENT PHASE - Network & System Isolation
# =================================================================

# File untuk mencatat IP yang diblokir
BLOCKED_IPS_FILE="$LOG_DIR/blocked_ips.txt"

# File halaman maintenance
MAINTENANCE_PAGE_FILENAME="maintenance.html"

# File index utama
INDEX_FILENAME="index.html"

# =================================================================
# ERADICATION PHASE - Threat Removal
# =================================================================

# Direktori YARA rules
YARA_RULES_DIR="/var/ossec/etc/rules/yara"

# Socket path ClamAV daemon
CLAMD_SOCKET="/var/run/clamav/clamd.ctl"

# Pattern mencurigakan untuk deteksi (pisahkan dengan |||)
ERADICATION_SUSPICIOUS_PATTERNS="(?i)(eval\s*\(base64_decode\s*\()|||(?i)(passthru\s*\()|||(?i)(shell_exec\s*\()|||(?i)(system\s*\()|||(?i)(exec\s*\()|||(?i)(preg_replace\s*\(.*\/e\s*\))|||(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)|||(?i)(document\.write\s*\(\s*unescape\s*\()|||(?i)(<iframe\s*src\s*=\s*[\"']javascript:)|||(?i)(fsockopen|pfsockopen)\s*\("

# =================================================================
# RECOVERY PHASE - System Restoration
# =================================================================

# Password untuk restore (base64 encoded)
PASSWORD="$ENCODED_PASSWORD"

# Konfigurasi monitoring server
MONITOR_IP="$MONITORING_SERVER"
MONITOR_USER="$MONITORING_USER"
MONITORING_SERVER="$MONITORING_SERVER"
MONITORING_USER="$MONITORING_USER"
MONITORING_PASSWORD="$MONITORING_PASSWORD"

# Path backup remote
REMOTE_GIT_BACKUP_PATH="/home/soc-backup/git-backup"
REMOTE_BACKUP_PATH="$REMOTE_BACKUP_PATH"
REMOTE_DYNAMIC_BACKUP_PATH="/home/soc-backup/dynamic-backup"

# File identitas SSH
SSH_IDENTITY_FILE="/home/soc-backup/.ssh/id_rsa"

# Cache direktori untuk restore dinamis
LOCAL_DYNAMIC_RESTORE_CACHE_DIR="/tmp/soc-dynamic-restore-cache"

# Backup dinamis aktif (true/false)
BACKUP_DYNAMIC="true"

# Direktori dinamis yang akan di-backup (array bash format)
DYNAMIC_DIRS=("uploads" "cache" "temp" "logs")

# User dan group web server
WEB_SERVER_USER="$WEB_SERVER_USER"
WEB_SERVER_GROUP="$WEB_SERVER_GROUP"

# =================================================================
# POST-INCIDENT ACTIVITY - Documentation & Analysis
# =================================================================

# Konfigurasi MISP untuk threat intelligence
MISP_URL="$MISP_URL"
MISP_KEY="$MISP_KEY"
MISP_VERIFY_CERT="$MISP_VERIFY_CERT"

# Direktori untuk laporan insiden
INCIDENT_REPORTS_DIR="$LOG_DIR/reports"

# File audit log
AUDIT_LOG="$LOG_DIR/audit.log"

# File log untuk MISP integration
MISP_LOG_FILE="$LOG_DIR/misp.log"

# =================================================================
# OUTPUT FILES - File Output untuk Setiap Fase
# =================================================================

# File output untuk deteksi IoC
DETECTION_OUTPUT_FILE="/tmp/active_response_500550.log"
DETECTION_LOG_FILE="/tmp/find_last_500550_debug.log"
IOC_DATA_FILE="/tmp/detected_ioc_data.json"

# File output untuk containment
CONTAINMENT_LOG_FILE="/var/log/wazuh/active-response/containment.log"

# File output untuk eradication
ERADICATION_LOG_FILE="/var/log/wazuh/active-response/eradication.log"

# File output untuk restore
RESTORE_LOG_FILE="/var/log/wazuh/active-response/restore.log"
RESTORE_AUTO_LOG_FILE="/var/log/wazuh/active-response/restore_auto.log"

# =================================================================
# SYSTEM INTEGRATION - Integrasi dengan Sistem
# =================================================================

# Timeout untuk operasi (dalam detik)
COMMAND_TIMEOUT="300"
RESTORE_TIMEOUT="600"

# Retry attempts untuk operasi yang gagal
MAX_RETRY_ATTEMPTS="3"

# Interval retry (dalam detik)
RETRY_INTERVAL="30"

# =================================================================
# SECURITY SETTINGS - Pengaturan Keamanan
# =================================================================

# Mode debug (true/false)
DEBUG_MODE="false"

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL="INFO"

# Enkripsi backup (true/false)
ENCRYPT_BACKUP="false"

# Backup retention days
BACKUP_RETENTION_DAYS="30"
EOF

    # Set permissions
    run_command "chmod 600 '$config_dir/config.conf'" "Setting config file permissions"
    run_command "chown root:root '$config_dir/config.conf'" "Setting config file ownership"
    
    # Create symbolic link for backward compatibility
    run_command "mkdir -p '/etc/web-backup'" "Creating web-backup config directory"
    run_command "ln -sf '$config_dir/config.conf' '/etc/web-backup/config.conf'" "Creating symbolic link for backward compatibility"
    
    success_msg "File config.conf berhasil dibuat di $config_dir/config.conf"
}

# ==============================================================================
# FUNGSI INSTALASI WAZUH
# ==============================================================================

# Fungsi untuk mendapatkan interface utama
get_main_interface() {
    # Mendapatkan interface default yang terhubung ke internet
    local main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$main_interface" ]; then
        # Fallback: mengambil interface pertama yang aktif (bukan lo)
        main_interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi
    echo "$main_interface"
}

# Fungsi untuk mendapatkan gateway
get_default_gateway() {
    local gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# Fungsi untuk mendapatkan IP yang tersedia
get_available_ip() {
    local interface=$1
    local gateway=$2
    
    # Mendapatkan network prefix dari gateway
    local network_prefix=$(echo "$gateway" | cut -d. -f1-3)
    
    # Mencoba beberapa IP dalam range yang sama dengan gateway
    for i in {10..20}; do
        local test_ip="${network_prefix}.$i"
        if ! ping -c1 -W1 "$test_ip" &>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # Fallback ke IP default jika tidak ada yang tersedia
    echo "${network_prefix}.10"
}

# Fungsi untuk konfigurasi IP Statis
configure_static_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    local gateway=$4
    local dns1=$5
    local dns2=$6

    info_msg "Menerapkan konfigurasi IP statis: $ip pada interface $interface"

    # Buat direktori netplan jika belum ada
    mkdir -p /etc/netplan

    # Backup file konfigurasi network yang ada
    if [ -f "/etc/netplan/00-installer-config.yaml" ]; then
        cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.backup
    fi

    # Buat konfigurasi netplan baru dengan format yang benar
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${interface}:
      dhcp4: false
      addresses:
        - ${ip}/${netmask}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns1}, ${dns2}]
EOF

    # Set permission yang benar
    chown root:root /etc/netplan/00-installer-config.yaml
    chmod 0600 /etc/netplan/00-installer-config.yaml

    # Generate dan terapkan konfigurasi
    netplan generate

    # Terapkan konfigurasi dengan penanganan error
    if ! netplan apply; then
        warning_msg "Mencoba menerapkan konfigurasi dalam mode debug..."
        netplan --debug apply
    fi

    # Tunggu sebentar untuk interface up
    sleep 5

    # Verifikasi koneksi
    if ping -c 1 ${gateway} > /dev/null 2>&1; then
        success_msg "Konfigurasi IP statis berhasil diterapkan"
        return 0
    else
        error_exit "Gagal menerapkan konfigurasi IP statis"
        if [ -f "/etc/netplan/00-installer-config.yaml.backup" ]; then
            mv /etc/netplan/00-installer-config.yaml.backup /etc/netplan/00-installer-config.yaml
            chmod 0600 /etc/netplan/00-installer-config.yaml
            netplan apply
        fi
        return 1
    fi
}

# Fungsi untuk memeriksa persyaratan sistem Wazuh
check_wazuh_system_requirements() {
    info_msg "Memeriksa persyaratan sistem untuk Wazuh..."
    
    # Periksa RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 4096 ]; then
        warning_msg "RAM kurang dari 4GB. Wazuh membutuhkan minimal 4GB RAM"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Periksa disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        warning_msg "Ruang disk kurang dari 20GB. Wazuh membutuhkan minimal 20GB free space"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Fungsi untuk menangani error Wazuh
handle_wazuh_error() {
    local error_msg="$1"
    error_exit "Wazuh Error: $error_msg"
}

# Fungsi untuk generate perintah instalasi agent Wazuh
generate_wazuh_agent_command() {
    local server_ip=$1
    local WAZUH_VERSION="4.7.5"
    local ARCHITECTURE="amd64"

    info_msg "Membuat generator perintah instalasi Wazuh Agent"
    echo "IP Server Wazuh: $server_ip"

    # Input nama agent
    echo "Masukkan nomor atau nama untuk agent (default: ubuntu-agent):"
    read agent_name
    if [ -z "$agent_name" ]; then
        agent_name="ubuntu-agent"
    fi

    # Generate perintah instalasi
    local install_command="wget https://packages.wazuh.com/${WAZUH_VERSION%.*}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb && sudo WAZUH_MANAGER='${server_ip}' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='${agent_name}' dpkg -i ./wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb"

    # Simpan perintah ke file
    cat > /root/install_wazuh_agent.sh << EOF
#!/bin/bash

# Script instalasi Wazuh Agent
# Generated pada: $(date)
# Server: $server_ip
# Agent Name: $agent_name

$install_command

# Start Wazuh Agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Check status
sudo systemctl status wazuh-agent
EOF

    chmod +x /root/install_wazuh_agent.sh

    success_msg "Script instalasi agent telah dibuat: /root/install_wazuh_agent.sh"
    echo "Perintah instalasi untuk agent:"
    echo "$install_command"
    echo "Atau gunakan script yang telah dibuat:"
    echo "scp /root/install_wazuh_agent.sh user@agent-ip:~/"
    echo "ssh user@agent-ip 'sudo bash ~/install_wazuh_agent.sh'"

    # Tampilkan ringkasan
    echo "Ringkasan Agent Installation:"
    echo "1. Server IP: $server_ip"
    echo "2. Agent Name: $agent_name"
    echo "3. Wazuh Version: $WAZUH_VERSION"
    echo "4. Architecture: $ARCHITECTURE"
    echo "5. Agent Group: default"
}

# Fungsi untuk instalasi Wazuh
install_wazuh() {
    info_msg "Memulai instalasi Wazuh..."
    
    # Deteksi otomatis konfigurasi jaringan
    info_msg "Mendeteksi konfigurasi jaringan..."

    # Deteksi interface utama
    INTERFACE=$(get_main_interface)
    success_msg "Interface terdeteksi: $INTERFACE"

    # Deteksi gateway
    GATEWAY=$(get_default_gateway)
    if [ -z "$GATEWAY" ]; then
        warning_msg "Tidak dapat mendeteksi gateway. Menggunakan default gateway"
        GATEWAY="192.168.1.1"
    fi
    success_msg "Gateway terdeteksi: $GATEWAY"

    # Set IP statis yang tersedia
    STATIC_IP=$(get_available_ip "$INTERFACE" "$GATEWAY")
    success_msg "IP statis yang akan digunakan: $STATIC_IP"

    # Set konfigurasi default
    NETMASK="24"
    DNS1="8.8.8.8"
    DNS2="8.8.4.4"

    # Periksa persyaratan sistem
    check_wazuh_system_requirements

    # Terapkan konfigurasi IP statis
    info_msg "Menerapkan konfigurasi IP statis..."
    configure_static_ip "$STATIC_IP" "$INTERFACE" "$NETMASK" "$GATEWAY" "$DNS1" "$DNS2"

    # Buat direktori untuk menyimpan file instalasi
    INSTALL_DIR="/root/wazuh-install-files"
    mkdir -p ${INSTALL_DIR}
    cd ${INSTALL_DIR}

    # Download Wazuh installer
    info_msg "Mengunduh Wazuh installer..."
    if ! curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh; then
        handle_wazuh_error "Gagal mengunduh installer Wazuh"
    fi

    chmod +x wazuh-install.sh

    # Membuat config.yml
    cat > config.yml << EOF
nodes:
  indexer:
    - name: node-1
      ip: ${STATIC_IP}
      role: master
  server:
    - name: wazuh-1
      ip: ${STATIC_IP}
  dashboard:
    - name: dashboard
      ip: ${STATIC_IP}
EOF

    # Buat direktori untuk menyimpan kredensial
    CRED_DIR="/root/wazuh-credentials"
    mkdir -p ${CRED_DIR}
    chmod 700 ${CRED_DIR}

    # Menjalankan instalasi dengan penanganan error
    success_msg "Memulai instalasi Wazuh..."

    # Generate config files
    if ! ./wazuh-install.sh --generate-config-files; then
        handle_wazuh_error "Gagal generate config files"
    fi
    success_msg "Konfigurasi berhasil di-generate"

    # Install dan start Wazuh indexer
    if ! ./wazuh-install.sh --wazuh-indexer node-1; then
        handle_wazuh_error "Gagal instalasi wazuh indexer"
    fi
    success_msg "Wazuh indexer berhasil diinstal"

    # Tunggu indexer siap
    info_msg "Menunggu Wazuh indexer siap..."
    sleep 30

    # Start cluster
    if ! ./wazuh-install.sh --start-cluster; then
        handle_wazuh_error "Gagal memulai cluster"
    fi
    success_msg "Cluster berhasil dimulai"

    # Simpan password
    info_msg "Menyimpan kredensial..."
    tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O > ${CRED_DIR}/wazuh-passwords-full.txt
    chmod 600 ${CRED_DIR}/wazuh-passwords-full.txt

    # Install Wazuh server
    if ! ./wazuh-install.sh --wazuh-server wazuh-1; then
        handle_wazuh_error "Gagal instalasi wazuh server"
    fi
    success_msg "Wazuh server berhasil diinstal"

    # Tunggu server siap
    info_msg "Menunggu Wazuh server siap..."
    sleep 30

    # Install Wazuh dashboard
    if ! ./wazuh-install.sh --wazuh-dashboard dashboard; then
        handle_wazuh_error "Gagal instalasi wazuh dashboard"
    fi
    success_msg "Wazuh dashboard berhasil diinstal"

    # Ekstrak dan simpan password spesifik
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "admin" > ${CRED_DIR}/admin-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "wazuh" > ${CRED_DIR}/wazuh-passwords.txt
    cat ${CRED_DIR}/wazuh-passwords-full.txt | grep -A 1 "kibana" > ${CRED_DIR}/kibana-passwords.txt

    # Buat file rangkuman kredensial
    cat > ${CRED_DIR}/credentials-summary.txt << EOF
Wazuh Credentials Summary
========================
Tanggal Instalasi: $(date)
IP Server: ${STATIC_IP}

Lokasi File Kredensial:
- Password Lengkap: ${CRED_DIR}/wazuh-passwords-full.txt
- Password Admin: ${CRED_DIR}/admin-passwords.txt
- Password Wazuh: ${CRED_DIR}/wazuh-passwords.txt
- Password Kibana: ${CRED_DIR}/kibana-passwords.txt

Akses Dashboard: https://${STATIC_IP}
Default username: admin

Note: 
- Simpan file ini di tempat yang aman
- Ganti password default setelah login pertama
- Backup folder ${CRED_DIR} secara berkala
EOF

    # Set permission untuk file kredensial
    chmod 600 ${CRED_DIR}/*
    chown -R root:root ${CRED_DIR}

    # Tambahkan entri ke /etc/hosts
    echo "${STATIC_IP} node-1 wazuh-1 dashboard" >> /etc/hosts

    # Periksa status layanan
    info_msg "Memeriksa status layanan..."
    services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            success_msg "Service $service berjalan dengan baik"
        else
            warning_msg "Service $service tidak berjalan"
            systemctl status $service
            info_msg "Mencoba restart service ${service}..."
            systemctl restart $service
            sleep 5
            if systemctl is-active --quiet $service; then
                success_msg "Service $service berhasil direstart"
            else
                warning_msg "Service $service masih bermasalah"
            fi
        fi
    done

    # Simpan informasi konfigurasi
    cat > /root/wazuh-info.txt << EOF
Konfigurasi Wazuh:
=================
IP Address: ${STATIC_IP}
Interface: ${INTERFACE}
Netmask: ${NETMASK}
Gateway: ${GATEWAY}
DNS1: ${DNS1}
DNS2: ${DNS2}

Dashboard URL: https://${STATIC_IP}

Lokasi File Kredensial: ${CRED_DIR}
EOF

    success_msg "Instalasi Wazuh selesai!"
    echo "Anda dapat mengakses dashboard di: https://${STATIC_IP}"
    echo "Kredensial tersimpan di: ${CRED_DIR}"
    echo "Informasi konfigurasi tersimpan di: /root/wazuh-info.txt"

    # Generate script instalasi agent
    info_msg "Membuat script instalasi untuk Wazuh Agent..."
    generate_wazuh_agent_command "${STATIC_IP}"

    success_msg "Proses instalasi dan konfigurasi Wazuh selesai!"
    
    # Return ke direktori asal
    cd "$SCRIPT_DIR"
}

# ==============================================================================
# FUNGSI INSTALASI MISP
# ==============================================================================

# Function to check MISP dependencies
check_misp_dependencies() {
    info_msg "Checking MISP dependencies..."
    if ! command -v docker &> /dev/null; then
        error_exit "Error: 'docker' is not installed. Please install Docker first."
    fi
    if ! command -v docker-compose &> /dev/null; then
        error_exit "Error: 'docker-compose' is not installed. Please install Docker Compose first."
    fi
    success_msg "MISP dependencies are satisfied."
}

# Function to wait for MISP to become available
wait_for_misp() {
    info_msg "Waiting for MISP to become available... This may take several minutes."
    until curl --output /dev/null --silent --head --fail --insecure https://localhost; do
        printf '.'
        sleep 5
    done
    success_msg "MISP is up and running!"
}

# Function to install and setup MISP
install_misp() {
    info_msg "Memulai instalasi MISP..."
    
    # MISP Configuration
    MISP_INSTALL_DIR="/opt/misp-docker"
    MISP_DOCKER_COMPOSE_URL="https://raw.githubusercontent.com/misp/misp-docker/main/docker-compose.yml"
    
    # Detail untuk pengguna API yang akan dibuat
    ORG_NAME="Wazuh-IR-Automation"
    USER_EMAIL_FOR_KEY="wazuh-automation@localhost.local"
    USER_COMMENT="API key for Wazuh Active Response integration"
    
    check_misp_dependencies
    
    # Periksa apakah kontainer MISP sudah berjalan
    MISP_CONTAINER_ID=$(docker ps -q --filter "name=misp-server")
    
    if [ -z "$MISP_CONTAINER_ID" ]; then
        info_msg "MISP container not found. Starting installation process..."
        
        # 1. Buat direktori instalasi
        info_msg "Creating installation directory at ${MISP_INSTALL_DIR}..."
        run_command "mkdir -p '$MISP_INSTALL_DIR'" "Creating MISP installation directory"
        cd "$MISP_INSTALL_DIR"
        
        # 2. Unduh file docker-compose.yml
        info_msg "Downloading latest misp-docker docker-compose.yml..."
        run_command "curl -o docker-compose.yml '$MISP_DOCKER_COMPOSE_URL'" "Downloading MISP docker-compose file"
        
        # 3. Jalankan MISP menggunakan docker-compose
        info_msg "Starting MISP containers in detached mode (-d)..."
        run_command "docker-compose up -d" "Starting MISP containers"
        
        # 4. Tunggu hingga MISP benar-benar siap
        wait_for_misp
        
        success_msg "MISP installation completed successfully."
    else
        success_msg "MISP is already installed and running."
        # Pastikan kita berada di direktori yang benar untuk perintah exec
        cd "$MISP_INSTALL_DIR"
    fi
    
    # Pengambilan API Key
    info_msg "Attempting to create/retrieve API key for user '${USER_EMAIL_FOR_KEY}'..."
    
    # Dapatkan email admin default dari dalam kontainer
    ADMIN_EMAIL=$(docker-compose exec -T misp-server cat /var/www/MISP/app/Config/config.php | grep "'email' =>" | head -1 | sed "s/.*'email' => '\([^']*\)'.*/\1/")
    
    if [ -z "$ADMIN_EMAIL" ]; then
        warning_msg "Could not automatically determine admin email. Defaulting to 'admin@admin.test'."
        ADMIN_EMAIL="admin@admin.test"
    fi
    
    info_msg "Using admin email: ${ADMIN_EMAIL}"
    
    # Gunakan perintah 'cake' di dalam kontainer untuk membuat pengguna dan mendapatkan kuncinya
    API_KEY_OUTPUT=$(docker-compose exec -T misp-server \
        /var/www/MISP/app/Console/cake Admin setApiUser "$ADMIN_EMAIL" "$ORG_NAME" "$USER_EMAIL_FOR_KEY" "$USER_COMMENT")
    
    # Ekstrak kunci API dari output
    MISP_KEY=$(echo "$API_KEY_OUTPUT" | grep 'Auth key:' | awk '{print $3}')
    
    if [ -n "$MISP_KEY" ]; then
        success_msg "Successfully retrieved API Key!"
        echo "------------------------------------------------------------------"
        echo "Your MISP API Key is: $MISP_KEY"
        echo "------------------------------------------------------------------"
        echo "Simpan kunci ini di tempat yang aman. Anda akan membutuhkannya untuk"
        echo "mengkonfigurasi skrip integrasi Wazuh."
        
        # Update config.conf dengan API key yang baru
        if [ -f "/etc/soc-config/config.conf" ]; then
            sed -i "s/MISP_KEY=.*/MISP_KEY=\"$MISP_KEY\"/" /etc/soc-config/config.conf
            success_msg "MISP API Key berhasil diupdate di config.conf"
        fi
    else
        error_exit "Error: Failed to retrieve API Key."
        info_msg "Please check the logs using 'docker-compose logs -f' in '${MISP_INSTALL_DIR}'."
    fi
    
    success_msg "MISP setup completed successfully!"
}

# ==============================================================================
# FUNGSI INSTALASI SERVER MONITORING
# ==============================================================================

# Function to setup monitoring server (backup repository)
install_monitoring_server() {
    info_msg "Memulai instalasi Server Monitoring (Backup Repository)..."
    
    # Tentukan direktori untuk menyimpan backup
    info_msg "Menentukan direktori untuk menyimpan backup Git dan arsip dinamis..."
    read -r -p "Masukkan path direktori utama backup (default: /var/backup/web_backups): " MAIN_BACKUP_DIR
    MAIN_BACKUP_DIR=${MAIN_BACKUP_DIR:-/var/backup/web_backups}

    # Path untuk backup Git (repositori bare)
    GIT_BACKUP_SUBDIR="git_repo" # Nama subdirektori untuk Git
    ACTUAL_GIT_BACKUP_PATH="$MAIN_BACKUP_DIR/$GIT_BACKUP_SUBDIR"

    # Path untuk backup file dinamis (arsip .tar.gz)
    DYNAMIC_BACKUP_SUBDIR="dynamic_archives" # Nama subdirektori untuk arsip dinamis
    ACTUAL_DYNAMIC_BACKUP_PATH="$MAIN_BACKUP_DIR/$DYNAMIC_BACKUP_SUBDIR"

    # Buat direktori backup jika belum ada
    if [ ! -d "$ACTUAL_GIT_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup Git: $ACTUAL_GIT_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_GIT_BACKUP_PATH'" "Creating Git backup directory"
    fi
    if [ ! -d "$ACTUAL_DYNAMIC_BACKUP_PATH" ]; then
        info_msg "Membuat direktori backup dinamis: $ACTUAL_DYNAMIC_BACKUP_PATH"
        run_command "mkdir -p '$ACTUAL_DYNAMIC_BACKUP_PATH'" "Creating dynamic backup directory"
    fi

    # Membuat pengguna khusus untuk backup
    echo ""
    info_msg "Pengaturan Pengguna Khusus untuk Menerima Backup"
    echo "----------------------------------------------------"
    read -r -p "Apakah Anda ingin membuat pengguna sistem khusus untuk menerima backup via SSH? (y/n, default: y): " CREATE_USER
    CREATE_USER=${CREATE_USER:-y}

    BACKUP_USER="" # Akan diisi jika CREATE_USER=y

    if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]]; then
        read -r -p "Masukkan nama pengguna untuk backup (default: webbackupuser): " INPUT_BACKUP_USER
        BACKUP_USER=${INPUT_BACKUP_USER:-webbackupuser}
        
        if id "$BACKUP_USER" &>/dev/null; then
            info_msg "Pengguna '$BACKUP_USER' sudah ada."
        else
            info_msg "Membuat pengguna '$BACKUP_USER'..."
            run_command "useradd -r -m -s /bin/bash '$BACKUP_USER'" "Creating backup user"
            success_msg "Pengguna '$BACKUP_USER' berhasil dibuat."
        fi
        
        info_msg "Mengatur kepemilikan direktori backup untuk pengguna '$BACKUP_USER'..."
        run_command "chown -R '$BACKUP_USER:$BACKUP_USER' '$MAIN_BACKUP_DIR'" "Setting ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting permissions of backup directory"

        # Inisialisasi repository Git bare
        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH'..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
            read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "sudo -u '$BACKUP_USER' git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        
        # Mengatur SSH untuk pengguna backup
        USER_SSH_DIR="/home/$BACKUP_USER/.ssh"
        info_msg "Memastikan direktori SSH '$USER_SSH_DIR' dan 'authorized_keys' ada untuk pengguna '$BACKUP_USER'..."
        run_command "sudo -u '$BACKUP_USER' mkdir -p '$USER_SSH_DIR'" "Creating SSH directory for backup user"
        run_command "sudo -u '$BACKUP_USER' touch '$USER_SSH_DIR/authorized_keys'" "Creating authorized_keys file"
        run_command "sudo -u '$BACKUP_USER' chmod 700 '$USER_SSH_DIR'" "Setting SSH directory permissions"
        run_command "sudo -u '$BACKUP_USER' chmod 600 '$USER_SSH_DIR/authorized_keys'" "Setting authorized_keys permissions"
        success_msg "Setup direktori SSH untuk '$BACKUP_USER' selesai."
        
        echo ""
        info_msg "--- INSTRUKSI PENTING UNTUK SERVER WEB ---"
        echo "Untuk mengizinkan server web melakukan push backup ke server monitoring ini:"
        echo "1. Di SERVER WEB, pastikan Anda memiliki SSH key pair untuk user root (atau user yang menjalankan backup)."
        echo "   Kunci publiknya (biasanya di '/root/.ssh/id_rsa_web_backup.pub') perlu disalin."
        echo "2. Di SERVER MONITORING INI, tambahkan isi kunci publik tersebut ke dalam file:"
        echo "   $USER_SSH_DIR/authorized_keys"
        echo "3. Pastikan pengguna '$BACKUP_USER' adalah pemilik file tersebut dan memiliki izin yang benar (chmod 600)."
        echo "--------------------------------------------"

    else # Jika tidak membuat pengguna khusus, backup akan diterima oleh root
        BACKUP_USER="root" # Backup akan menggunakan root jika tidak ada user khusus
        warning_msg "PERINGATAN: Tidak ada pengguna khusus yang dibuat. Backup akan diterima sebagai pengguna 'root'. Ini kurang aman."
        info_msg "Pastikan direktori '$MAIN_BACKUP_DIR' dapat ditulis oleh root."
        run_command "chown -R 'root:root' '$MAIN_BACKUP_DIR'" "Setting root ownership of backup directory"
        run_command "chmod -R u=rwx,g=,o= '$MAIN_BACKUP_DIR'" "Setting root permissions of backup directory"

        info_msg "Menginisialisasi repository Git bare di '$ACTUAL_GIT_BACKUP_PATH' sebagai root..."
        if [ -d "$ACTUAL_GIT_BACKUP_PATH/.git" ] || [ "$(ls -A "$ACTUAL_GIT_BACKUP_PATH")" ]; then
             read -r -p "Direktori '$ACTUAL_GIT_BACKUP_PATH' sudah ada isinya atau tampak seperti repo. Inisialisasi ulang? (Data lama di path ini akan hilang jika ya) (y/N): " REINIT_BARE_GIT
            REINIT_BARE_GIT=${REINIT_BARE_GIT:-N}
            if [[ "$REINIT_BARE_GIT" == "y" || "$REINIT_BARE_GIT" == "Y" ]]; then
                run_command "rm -rf '${ACTUAL_GIT_BACKUP_PATH:?}/'*" "Removing existing Git repository"
                run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Reinitializing Git bare repository as root"
                success_msg "Repository Git bare berhasil diinisialisasi ulang."
            else
                info_msg "Inisialisasi Git bare dilewati."
            fi
        else
            run_command "git init --bare '$ACTUAL_GIT_BACKUP_PATH'" "Initializing Git bare repository as root"
            success_msg "Repository Git bare berhasil diinisialisasi."
        fi
        info_msg "SSH key dari server web perlu ditambahkan ke '/root/.ssh/authorized_keys' di server monitoring ini."
    fi

    # Konfigurasi Monitoring Server Ini Sendiri (Opsional)
    echo ""
    info_msg "Konfigurasi Monitoring untuk Server Backup Ini Sendiri (Opsional)"
    echo "-------------------------------------------------------------------"
    read -r -p "Apakah Anda ingin menginstal Wazuh Agent untuk memonitor server backup ini sendiri? (y/n, default: n): " INSTALL_WAZUH_AGENT_LOCAL
    INSTALL_WAZUH_AGENT_LOCAL=${INSTALL_WAZUH_AGENT_LOCAL:-n}

    if [[ "$INSTALL_WAZUH_AGENT_LOCAL" == "y" || "$INSTALL_WAZUH_AGENT_LOCAL" == "Y" ]]; then
        info_msg "Memulai instalasi Wazuh Agent untuk server backup ini..."
        
        if ! command -v apt-key &> /dev/null || ! command -v tee &> /dev/null ; then
            run_command "apt-get install -y gnupg apt-transport-https" "Installing gnupg and apt-transport-https"
        fi

        run_command "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg" "Importing Wazuh GPG key"
        run_command "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list" "Adding Wazuh repository"
        
        run_command "apt-get update -y" "Updating package list after adding Wazuh repository"
        run_command "apt-get install -y wazuh-agent" "Installing Wazuh Agent"
        
        read -r -p "Masukkan alamat IP Wazuh Manager untuk agent ini: " WAZUH_MANAGER_IP_FOR_AGENT
        while [[ -z "$WAZUH_MANAGER_IP_FOR_AGENT" ]]; do
            read -r -p "Alamat IP Wazuh Manager tidak boleh kosong. Masukkan IP: " WAZUH_MANAGER_IP_FOR_AGENT
        done
        
        # Konfigurasi Wazuh Agent (ossec.conf)
        run_command "sed -i 's|<address>MANAGER_IP</address>|<address>$WAZUH_MANAGER_IP_FOR_AGENT</address>|g' /var/ossec/etc/ossec.conf" "Configuring Wazuh Agent manager IP"
        
        run_command "systemctl daemon-reload" "Reloading systemd daemon"
        run_command "systemctl enable wazuh-agent" "Enabling Wazuh Agent service"
        run_command "systemctl restart wazuh-agent" "Starting Wazuh Agent service"
        
        success_msg "Wazuh Agent berhasil diinstal dan dikonfigurasi untuk memonitor server backup ini."
        info_msg "Pastikan untuk mendaftarkan agent ini di Wazuh Manager."
    else
        info_msg "Instalasi Wazuh Agent untuk server backup ini dilewati."
    fi

    # Konfigurasi Git Hooks untuk Notifikasi (opsional)
    echo ""
    info_msg "Konfigurasi Git Hook untuk Notifikasi Email (Opsional)"
    echo "---------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur notifikasi email setiap kali backup Git diterima? (y/n, default: n): " SETUP_NOTIFICATION
    SETUP_NOTIFICATION=${SETUP_NOTIFICATION:-n}

    if [[ "$SETUP_NOTIFICATION" == "y" || "$SETUP_NOTIFICATION" == "Y" ]]; then
        if ! command -v mail &> /dev/null; then
            info_msg "Command 'mail' (mailutils) tidak ditemukan. Menginstal..."
            run_command "apt-get install -y mailutils" "Installing mailutils for email notifications"
        fi

        if command -v mail &> /dev/null; then
            read -r -p "Masukkan alamat email untuk notifikasi: " NOTIFY_EMAIL
            while [[ -z "$NOTIFY_EMAIL" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " NOTIFY_EMAIL
            done
            
            HOOK_DIR="$ACTUAL_GIT_BACKUP_PATH/hooks"
            HOOK_FILE="$HOOK_DIR/post-receive"

            info_msg "Membuat direktori hook $HOOK_DIR jika belum ada..."
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "sudo -u '$BACKUP_USER' mkdir -p '$HOOK_DIR'" "Creating hook directory as backup user"
            else
                run_command "mkdir -p '$HOOK_DIR'" "Creating hook directory"
            fi

            info_msg "Membuat skrip post-receive hook di $HOOK_FILE..."
            cat > "$HOOK_FILE" << EOF_HOOK
#!/bin/bash
# Git hook untuk mengirim notifikasi email saat menerima backup baru

REPO_NAME="\$(basename "\$(pwd)")"
COMMIT_INFO=\$(git log -1 --pretty=format:"%h - %an, %ar : %s")
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
TIMESTAMP=\$(date +"%Y-%m-%d %H:%M:%S")

mail -s "Backup GIT Baru Diterima di \$SERVER_HOSTNAME untuk \$REPO_NAME" "$NOTIFY_EMAIL" << EOM_MAIL
Backup Git baru telah diterima di server monitoring: \$SERVER_HOSTNAME

Repository Path: \$(pwd)
Timestamp: \$TIMESTAMP
Commit Terakhir: \$COMMIT_INFO

Pesan ini dikirim otomatis dari hook post-receive.
EOM_MAIL
EOF_HOOK

            run_command "chmod +x '$HOOK_FILE'" "Making hook file executable"
            if [[ "$CREATE_USER" == "y" || "$CREATE_USER" == "Y" ]] && id "$BACKUP_USER" &>/dev/null; then
                run_command "chown '$BACKUP_USER:$BACKUP_USER' '$HOOK_FILE'" "Setting hook file ownership to backup user"
                info_msg "Kepemilikan hook diatur ke $BACKUP_USER."
            fi
            success_msg "Notifikasi email untuk backup Git baru telah dikonfigurasi di $HOOK_FILE."
            info_msg "Pastikan MTA (seperti Postfix atau ssmtp) terkonfigurasi di server ini agar perintah 'mail' berfungsi."
        else
            warning_msg "Gagal menginstal atau menemukan 'mail'. Notifikasi email dilewati."
        fi
    fi

    # Monitoring disk space untuk MAIN_BACKUP_DIR (opsional)
    echo ""
    info_msg "Monitoring Disk Space untuk Direktori Backup (Opsional)"
    echo "-----------------------------------------------------------"
    read -r -p "Apakah Anda ingin mengatur monitoring disk space untuk '$MAIN_BACKUP_DIR'? (y/n, default: y): " SETUP_DISK_MONITORING
    SETUP_DISK_MONITORING=${SETUP_DISK_MONITORING:-y}

    if [[ "$SETUP_DISK_MONITORING" == "y" || "$SETUP_DISK_MONITORING" == "Y" ]]; then
        if ! command -v mail &> /dev/null && ! command -v mailx &> /dev/null ; then
            info_msg "Command 'mail' atau 'mailx' tidak ditemukan. Menginstal mailutils..."
            run_command "apt-get install -y mailutils" "Installing mailutils for disk monitoring"
        fi

        if command -v mail &> /dev/null || command -v mailx &> /dev/null ; then
            MONITOR_SCRIPT_PATH="/usr/local/bin/monitor_backup_disk_space.sh"
            info_msg "Membuat skrip monitoring disk di $MONITOR_SCRIPT_PATH..."

            cat > "$MONITOR_SCRIPT_PATH" << EOF_DISK_MON
#!/bin/bash
# Skrip untuk memonitor penggunaan disk direktori backup

TARGET_BACKUP_DIR="\$1"
USAGE_THRESHOLD="\$2" # Persentase, misal 80
EMAIL_RECIPIENT="\$3"
SERVER_HOSTNAME=\$(hostname -f 2>/dev/null || hostname)
LOG_FILE="/var/log/backup_disk_monitor.log"
MAIL_COMMAND=\$(command -v mail || command -v mailx)

if [ -z "\$MAIL_COMMAND" ]; then
    echo "[\$(date)] Error: Perintah mail/mailx tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

if [ ! -d "\$TARGET_BACKUP_DIR" ]; then
    echo "[\$(date)] Error: Direktori backup '\$TARGET_BACKUP_DIR' tidak ditemukan." >> "\$LOG_FILE"
    exit 1
fi

CURRENT_USAGE=\$(df "\$TARGET_BACKUP_DIR" | awk 'NR==2 {print \$5}' | sed 's/%//')

if [ -z "\$CURRENT_USAGE" ]; then
    echo "[\$(date)] Error: Tidak dapat mengambil info penggunaan disk untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
    exit 1
fi

if [ "\$CURRENT_USAGE" -gt "\$USAGE_THRESHOLD" ]; then
    SUBJECT="[PERINGATAN] Disk Backup di \$SERVER_HOSTNAME Hampir Penuh (\$CURRENT_USAGE%)"
    MESSAGE="Penggunaan disk pada direktori backup '\$TARGET_BACKUP_DIR' di server \$SERVER_HOSTNAME telah mencapai \$CURRENT_USAGE% (Threshold: \$USAGE_THRESHOLD%).\n\nDetail Penggunaan Disk:\n\$(df -h "\$TARGET_BACKUP_DIR")\n\nHarap segera periksa dan kosongkan ruang jika perlu."
    
    echo -e "\$MESSAGE" | \$MAIL_COMMAND -s "\$SUBJECT" "\$EMAIL_RECIPIENT"
    echo "[\$(date)] Peringatan Terkirim: Penggunaan disk \$CURRENT_USAGE% melebihi threshold \$USAGE_THRESHOLD% untuk '\$TARGET_BACKUP_DIR'." >> "\$LOG_FILE"
else
    echo "[\$(date)] Info: Penggunaan disk \$CURRENT_USAGE% untuk '\$TARGET_BACKUP_DIR' masih di bawah threshold \$USAGE_THRESHOLD%." >> "\$LOG_FILE"
fi
exit 0
EOF_DISK_MON
            run_command "chmod +x '$MONITOR_SCRIPT_PATH'" "Making disk monitoring script executable"
            success_msg "Skrip monitoring disk $MONITOR_SCRIPT_PATH berhasil dibuat."

            read -r -p "Masukkan threshold penggunaan disk dalam persen (misal 80, default: 80): " DISK_THRESHOLD_INPUT
            DISK_THRESHOLD_INPUT=${DISK_THRESHOLD_INPUT:-80}
            read -r -p "Masukkan alamat email untuk notifikasi disk space: " DISK_EMAIL_INPUT
            while [[ -z "$DISK_EMAIL_INPUT" ]]; do
                read -r -p "Alamat email tidak boleh kosong. Masukkan alamat email: " DISK_EMAIL_INPUT
            done
            
            CRON_DISK_MON_ENTRY="0 7 * * * $MONITOR_SCRIPT_PATH \"$MAIN_BACKUP_DIR\" \"$DISK_THRESHOLD_INPUT\" \"$DISK_EMAIL_INPUT\""
            
            # Tambahkan ke crontab root
            run_command "(crontab -l 2>/dev/null | grep -vF '$MONITOR_SCRIPT_PATH'; echo '$CRON_DISK_MON_ENTRY') | crontab -" "Adding disk monitoring to crontab"
            success_msg "Monitoring disk space untuk direktori backup '$MAIN_BACKUP_DIR' telah diatur via cron."
            info_msg "Log monitoring disk akan ada di /var/log/backup_disk_monitor.log"
        else
            warning_msg "Gagal menginstal atau menemukan 'mail/mailx'. Monitoring disk space dilewati."
        fi
    fi

    SERVER_IP_ADDRESS=$(hostname -I | awk '{print $1}') # Ambil IP utama

    echo ""
    echo "================================================================="
    echo "      INSTALASI SERVER MONITORING BERHASIL DISELESAIKAN         "
    echo "================================================================="
    echo ""
    echo "Informasi Penting untuk Konfigurasi Server Web:"
    echo "----------------------------------------------"
    echo "IP Server Monitoring Ini: ${SERVER_IP_ADDRESS:-Mohon periksa manual}"
    echo "Pengguna SSH untuk Backup: $BACKUP_USER"
    echo "Path Tujuan Backup Git: $ACTUAL_GIT_BACKUP_PATH"
    echo "Path Tujuan Backup Dinamis (arsip): $ACTUAL_DYNAMIC_BACKUP_PATH"
    echo ""
    echo "Contoh Perintah di Server Web untuk Menambahkan Remote Git:"
    echo "   git remote add monitoring $BACKUP_USER@${SERVER_IP_ADDRESS:-<IP_SERVER_MONITORING>}:$ACTUAL_GIT_BACKUP_PATH"
    echo ""
    echo "CATATAN PENTING:"
    echo "- Format URL Git SSH yang disarankan: '$BACKUP_USER@<IP_SERVER_MONITORING>:$ACTUAL_GIT_BACKUP_PATH' (gunakan path absolut)."
    echo "- Pastikan kunci SSH publik dari server web (user root atau yang menjalankan backup) telah ditambahkan ke:"
    echo "  '/home/$BACKUP_USER/.ssh/authorized_keys' (jika $BACKUP_USER dibuat) atau '/root/.ssh/authorized_keys' (jika tidak ada user khusus) di server monitoring ini."
    echo "- Pastikan direktori '$ACTUAL_DYNAMIC_BACKUP_PATH' dapat ditulis oleh '$BACKUP_USER' (atau root) melalui rsync/scp."
    echo ""
    echo "Server monitoring ini sekarang siap menerima backup."
    echo "================================================================="
}

# ==============================================================================
# FUNGSI KONFIGURASI SOC
# ==============================================================================

# Function to collect user input for configuration
collect_user_config() {
    info_msg "Mengumpulkan konfigurasi dari user..."
    
    # Web directory
    read -r -p "Masukkan path direktori web server (default: /var/www/html): " WEB_DIR
    WEB_DIR=${WEB_DIR:-/var/www/html}
    
    # Backup directory
    read -r -p "Masukkan path direktori backup (default: /var/soc-backup): " BACKUP_DIR
    BACKUP_DIR=${BACKUP_DIR:-/var/soc-backup}
    
    # Quarantine directory
    read -r -p "Masukkan path direktori karantina (default: /var/soc-quarantine): " QUARANTINE_DIR
    QUARANTINE_DIR=${QUARANTINE_DIR:-/var/soc-quarantine}
    
    # Log directory
    read -r -p "Masukkan path direktori log (default: /var/log/soc-incident-response): " LOG_DIR
    LOG_DIR=${LOG_DIR:-/var/log/soc-incident-response}
    
    # Wazuh alerts file
    read -r -p "Masukkan path file alerts Wazuh (default: /var/ossec/logs/alerts/alerts.json): " WAZUH_ALERTS_FILE
    WAZUH_ALERTS_FILE=${WAZUH_ALERTS_FILE:-/var/ossec/logs/alerts/alerts.json}
    
    # Rule IDs
    read -r -p "Masukkan Rule IDs untuk defacement (default: 550,554,5501,5502,5503,5504,100001,100002): " DEFACE_RULE_IDS
    DEFACE_RULE_IDS=${DEFACE_RULE_IDS:-550,554,5501,5502,5503,5504,100001,100002}
    
    read -r -p "Masukkan Rule IDs untuk serangan (default: 5710,5712,5715,5760,100003,100004): " ATTACK_RULE_IDS
    ATTACK_RULE_IDS=${ATTACK_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk eradication (default: 5710,5712,5715,5760,100003,100004): " ERADICATION_RULE_IDS
    ERADICATION_RULE_IDS=${ERADICATION_RULE_IDS:-5710,5712,5715,5760,100003,100004}
    
    read -r -p "Masukkan Rule IDs untuk restore (default: 100010,100011,100012): " RESTORE_RULE_IDS
    RESTORE_RULE_IDS=${RESTORE_RULE_IDS:-100010,100011,100012}
    
    # MISP Configuration
    read -r -p "Masukkan URL MISP (default: https://192.168.28.135): " MISP_URL
    MISP_URL=${MISP_URL:-https://192.168.28.135}
    
    read -r -p "Masukkan API Key MISP: " MISP_KEY
    if [[ -z "$MISP_KEY" ]]; then
        MISP_KEY="XweOnEWOtWFmIbW585H2m03R3SIZRmIKxrza73WB"
        warning_msg "Menggunakan API Key default MISP"
    fi
    
    read -r -p "Verifikasi sertifikat MISP? (y/n, default: n): " MISP_VERIFY_CERT
    if [[ "$MISP_VERIFY_CERT" =~ ^[Yy]$ ]]; then
        MISP_VERIFY_CERT="true"
    else
        MISP_VERIFY_CERT="false"
    fi
    
    # Monitoring server
    while true; do
        read -r -p "Masukkan IP server monitoring (default: 192.168.1.100): " MONITORING_SERVER
        MONITORING_SERVER=${MONITORING_SERVER:-192.168.1.100}
        if validate_ip "$MONITORING_SERVER"; then
            break
        else
            warning_msg "IP address tidak valid. Silakan coba lagi."
        fi
    done
    
    read -r -p "Masukkan username server monitoring (default: soc-backup): " MONITORING_USER
    MONITORING_USER=${MONITORING_USER:-soc-backup}
    
    read -s -p "Masukkan password server monitoring: " MONITORING_PASSWORD
    echo
    
    # Backup paths
    read -r -p "Masukkan path backup remote (default: /home/soc-backup/backups): " REMOTE_BACKUP_PATH
    REMOTE_BACKUP_PATH=${REMOTE_BACKUP_PATH:-/home/soc-backup/backups}
    
    # Web server user/group
    read -r -p "Masukkan user web server (default: www-data): " WEB_SERVER_USER
    WEB_SERVER_USER=${WEB_SERVER_USER:-www-data}
    
    read -r -p "Masukkan group web server (default: www-data): " WEB_SERVER_GROUP
    WEB_SERVER_GROUP=${WEB_SERVER_GROUP:-www-data}
    
    # Password untuk restore
    read -s -p "Masukkan password untuk restore (minimal 12 karakter): " RESTORE_PASSWORD
    echo
    if [[ ${#RESTORE_PASSWORD} -lt 12 ]]; then
        error_exit "Password harus minimal 12 karakter"
    fi
    ENCODED_PASSWORD=$(echo -n "$RESTORE_PASSWORD" | base64)
    
    success_msg "Konfigurasi user berhasil dikumpulkan"
}

# Function to create config.conf from user input
create_config_file() {
    info_msg "Membuat file config.conf..."
    
    local config_dir="/etc/soc-config"
    run_command "mkdir -p '$config_dir'" "Creating SOC config directory"
    
    cat > "$config_dir/config.conf" << EOF
# =================================================================
# SOC INCIDENT RESPONSE CONFIGURATION - NIST 800-61r2 FRAMEWORK
# =================================================================
# File konfigurasi terpusat untuk semua script IRLC
# Sesuai dengan NIST 800-61r2: Preparation, Detection & Analysis, 
# Containment, Eradication, Recovery, dan Post-Incident Activity

# =================================================================
# PREPARATION PHASE - Konfigurasi Dasar Sistem
# =================================================================

# Direktori web yang akan diproteksi
WEB_DIR="$WEB_DIR"

# Direktori backup utama
BACKUP_DIR="$BACKUP_DIR"

# Direktori karantina untuk file mencurigakan
QUARANTINE_DIR="$QUARANTINE_DIR"

# Direktori log untuk semua aktivitas IRLC
LOG_DIR="$LOG_DIR"

# Direktori konfigurasi SOC
SOC_CONFIG_DIR="$config_dir"

# =================================================================
# DETECTION & ANALYSIS PHASE - Wazuh Integration
# =================================================================

# File alerts.json utama Wazuh
WAZUH_ALERTS_FILE="$WAZUH_ALERTS_FILE"

# Direktori log Wazuh active response
WAZUH_ACTIVE_RESPONSE_LOG_DIR="/var/log/wazuh/active-response"

# Rule IDs untuk deteksi defacement
DEFACE_RULE_IDS="$DEFACE_RULE_IDS"

# Rule IDs untuk deteksi serangan
ATTACK_RULE_IDS="$ATTACK_RULE_IDS"

# Rule IDs untuk trigger eradication
ERADICATION_RULE_IDS="$ERADICATION_RULE_IDS"

# Rule IDs untuk trigger auto restore
RESTORE_RULE_IDS="$RESTORE_RULE_IDS"

# =================================================================
# CONTAINMENT PHASE - Network & System Isolation
# =================================================================

# File untuk mencatat IP yang diblokir
BLOCKED_IPS_FILE="$LOG_DIR/blocked_ips.txt"

# File halaman maintenance
MAINTENANCE_PAGE_FILENAME="maintenance.html"

# File index utama
INDEX_FILENAME="index.html"

# =================================================================
# ERADICATION PHASE - Threat Removal
# =================================================================

# Direktori YARA rules
YARA_RULES_DIR="/var/ossec/etc/rules/yara"

# Socket path ClamAV daemon
CLAMD_SOCKET="/var/run/clamav/clamd.ctl"

# Pattern mencurigakan untuk deteksi (pisahkan dengan |||)
ERADICATION_SUSPICIOUS_PATTERNS="(?i)(eval\s*\(base64_decode\s*\()|||(?i)(passthru\s*\()|||(?i)(shell_exec\s*\()|||(?i)(system\s*\()|||(?i)(exec\s*\()|||(?i)(preg_replace\s*\(.*\/e\s*\))|||(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)|||(?i)(document\.write\s*\(\s*unescape\s*\()|||(?i)(<iframe\s*src\s*=\s*[\"']javascript:)|||(?i)(fsockopen|pfsockopen)\s*\("

# =================================================================
# RECOVERY PHASE - System Restoration
# =================================================================

# Password untuk restore (base64 encoded)
PASSWORD="$ENCODED_PASSWORD"

# Konfigurasi monitoring server
MONITOR_IP="$MONITORING_SERVER"
MONITOR_USER="$MONITORING_USER"
MONITORING_SERVER="$MONITORING_SERVER"
MONITORING_USER="$MONITORING_USER"
MONITORING_PASSWORD="$MONITORING_PASSWORD"

# Path backup remote
REMOTE_GIT_BACKUP_PATH="/home/soc-backup/git-backup"
REMOTE_BACKUP_PATH="$REMOTE_BACKUP_PATH"
REMOTE_DYNAMIC_BACKUP_PATH="/home/soc-backup/dynamic-backup"

# File identitas SSH
SSH_IDENTITY_FILE="/home/soc-backup/.ssh/id_rsa"

# Cache direktori untuk restore dinamis
LOCAL_DYNAMIC_RESTORE_CACHE_DIR="/tmp/soc-dynamic-restore-cache"

# Backup dinamis aktif (true/false)
BACKUP_DYNAMIC="true"

# Direktori dinamis yang akan di-backup (array bash format)
DYNAMIC_DIRS=("uploads" "cache" "temp" "logs")

# User dan group web server
WEB_SERVER_USER="$WEB_SERVER_USER"
WEB_SERVER_GROUP="$WEB_SERVER_GROUP"

# =================================================================
# POST-INCIDENT ACTIVITY - Documentation & Analysis
# =================================================================

# Konfigurasi MISP untuk threat intelligence
MISP_URL="$MISP_URL"
MISP_KEY="$MISP_KEY"
MISP_VERIFY_CERT="$MISP_VERIFY_CERT"

# Direktori untuk laporan insiden
INCIDENT_REPORTS_DIR="$LOG_DIR/reports"

# File audit log
AUDIT_LOG="$LOG_DIR/audit.log"

# File log untuk MISP integration
MISP_LOG_FILE="$LOG_DIR/misp.log"

# =================================================================
# OUTPUT FILES - File Output untuk Setiap Fase
# =================================================================

# File output untuk deteksi IoC
DETECTION_OUTPUT_FILE="/tmp/active_response_500550.log"
DETECTION_LOG_FILE="/tmp/find_last_500550_debug.log"
IOC_DATA_FILE="/tmp/detected_ioc_data.json"

# File output untuk containment
CONTAINMENT_LOG_FILE="/var/log/wazuh/active-response/containment.log"

# File output untuk eradication
ERADICATION_LOG_FILE="/var/log/wazuh/active-response/eradication.log"

# File output untuk restore
RESTORE_LOG_FILE="/var/log/wazuh/active-response/restore.log"
RESTORE_AUTO_LOG_FILE="/var/log/wazuh/active-response/restore_auto.log"

# =================================================================
# SYSTEM INTEGRATION - Integrasi dengan Sistem
# =================================================================

# Timeout untuk operasi (dalam detik)
COMMAND_TIMEOUT="300"
RESTORE_TIMEOUT="600"

# Retry attempts untuk operasi yang gagal
MAX_RETRY_ATTEMPTS="3"

# Interval retry (dalam detik)
RETRY_INTERVAL="30"

# =================================================================
# SECURITY SETTINGS - Pengaturan Keamanan
# =================================================================

# Mode debug (true/false)
DEBUG_MODE="false"

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL="INFO"

# Enkripsi backup (true/false)
ENCRYPT_BACKUP="false"

# Backup retention days
BACKUP_RETENTION_DAYS="30"
EOF

    # Set permissions
    run_command "chmod 600 '$config_dir/config.conf'" "Setting config file permissions"
    run_command "chown root:root '$config_dir/config.conf'" "Setting config file ownership"
    
    # Create symbolic link for backward compatibility
    run_command "mkdir -p '/etc/web-backup'" "Creating web-backup config directory"
    run_command "ln -sf '$config_dir/config.conf' '/etc/web-backup/config.conf'" "Creating symbolic link for backward compatibility"
    
    success_msg "File config.conf berhasil dibuat di $config_dir/config.conf"
}

# ==============================================================================
# FUNGSI INSTALASI WAZUH
# ==============================================================================

# Fungsi untuk mendapatkan interface utama
get_main_interface() {
    # Mendapatkan interface default yang terhubung ke internet
    local main_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$main_interface" ]; then
        # Fallback: mengambil interface pertama yang aktif (bukan lo)
        main_interface=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | head -n1)
    fi
    echo "$main_interface"
}

# Fungsi untuk mendapatkan gateway
get_default_gateway() {
    local gateway=$(ip route | grep default | awk '{print $3}' | head -n1)
    echo "$gateway"
}

# Fungsi untuk mendapatkan IP yang tersedia
get_available_ip() {
    local interface=$1
    local gateway=$2
    
    # Mendapatkan network prefix dari gateway
    local network_prefix=$(echo "$gateway" | cut -d. -f1-3)
    
    # Mencoba beberapa IP dalam range yang sama dengan gateway
    for i in {10..20}; do
        local test_ip="${network_prefix}.$i"
        if ! ping -c1 -W1 "$test_ip" &>/dev/null; then
            echo "$test_ip"
            return 0
        fi
    done
    
    # Fallback ke IP default jika tidak ada yang tersedia
    echo "${network_prefix}.10"
}

# Fungsi untuk konfigurasi IP Statis
configure_static_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    local gateway=$4
    local dns1=$5
    local dns2=$6

    info_msg "Menerapkan konfigurasi IP statis: $ip pada interface $interface"

    # Buat direktori netplan jika belum ada
    mkdir -p /etc/netplan

    # Backup file konfigurasi network yang ada
    if [ -f "/etc/netplan/00-installer-config.yaml" ]; then
        cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.backup
    fi

    # Buat konfigurasi netplan baru dengan format yang benar
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${interface}:
      dhcp4: false
      addresses:
        - ${ip}/${netmask}
      routes:
        - to: default
          via: ${gateway}
      nameservers:
        addresses: [${dns1}, ${dns2}]
EOF

    # Set permission yang benar
    chown root:root /etc/netplan/00-installer-config.yaml
    chmod 0600 /etc/netplan/00-installer-config.yaml

    # Generate dan terapkan konfigurasi
    netplan generate

    # Terapkan konfigurasi dengan penanganan error
    if ! netplan apply; then
        warning_msg "Mencoba menerapkan konfigurasi dalam mode debug..."
        netplan --debug apply
    fi

    # Tunggu sebentar untuk interface up
    sleep 5

    # Verifikasi koneksi
    if ping -c 1 ${gateway} > /dev/null 2>&1; then
        success_msg "Konfigurasi IP statis berhasil diterapkan"
        return 0
    else
        error_exit "Gagal menerapkan konfigurasi IP statis"
        if [ -f "/etc/netplan/00-installer-config.yaml.backup" ]; then
            mv /etc/netplan/00-installer-config.yaml.backup /etc/netplan/00-installer-config.yaml
            chmod 0600 /etc/netplan/00-installer-config.yaml
            netplan apply
        fi
        return 1
    fi
}

# Fungsi untuk memeriksa persyaratan sistem Wazuh
check_wazuh_system_requirements() {
    info_msg "Memeriksa persyaratan sistem untuk Wazuh..."
    
    # Periksa RAM
    total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt 4096 ]; then
        warning_msg "RAM kurang dari 4GB. Wazuh membutuhkan minimal 4GB RAM"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Periksa disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 10240 ]; then
        warning_msg "Ruang disk kurang dari 20GB. Wazuh membutuhkan minimal 20GB free space"
        read -p "Lanjutkan instalasi? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Fungsi untuk menangani error Wazuh
handle_wazuh_error() {
    local error_msg="$1"
    error_exit "Wazuh Error: $error_msg"
}

# Fungsi untuk generate perintah instalasi agent Wazuh
generate_wazuh_agent_command() {
    local server_ip=$1
    local WAZUH_VERSION="4.7.5"
    local ARCHITECTURE="amd64"

    info_msg "Membuat generator perintah instalasi Wazuh Agent"
    echo "IP Server Wazuh: $server_ip"

    # Input nama agent
    echo "Masukkan nomor atau nama untuk agent (default: ubuntu-agent):"
    read agent_name
    if [ -z "$agent_name" ]; then
        agent_name="ubuntu-agent"
    fi

    # Generate perintah instalasi
    local install_command="wget https://packages.wazuh.com/${WAZUH_VERSION%.*}/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb && sudo WAZUH_MANAGER='${server_ip}' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='${agent_name}' dpkg -i ./wazuh-agent_${WAZUH_VERSION}-1_${ARCHITECTURE}.deb"

    # Simpan perintah ke file
    cat > /root/install_wazuh_agent.sh << EOF
#!/bin/bash

# Script instalasi Wazuh Agent
# Generated pada: $(date)
# Server: $server_ip
# Agent Name: $agent_name

$install_command

# Start Wazuh Agent service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Check status
sudo systemctl status wazuh-agent
EOF

    chmod +x /root/install_wazuh_agent.sh

    success_msg "Script instalasi agent telah dibuat: /root/install_wazuh_agent.sh"
    echo "Perintah instalasi untuk agent:"
    echo "$install_command"
    echo "Atau gunakan script yang telah dibuat:"
    echo "scp /root/install_wazuh_agent.sh user@agent-ip:~/"
    echo "ssh user@agent-ip 'sudo bash ~/install_wazuh_agent.sh'"

    # Tampilkan ringkasan
    echo "Ringkasan Agent Installation:"
    echo "1