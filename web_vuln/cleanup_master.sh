#!/bin/bash

# =================================================================
# CLEANUP MASTER - INTEGRATED CLEANUP SOLUTION
# =================================================================
# Script terintegrasi untuk menghapus semua website vulnerable
# =================================================================

# Konfigurasi
WEB_DIR="/var/www/html"
WP_DIR="$WEB_DIR/wordpress"
GOV_DIR="$WEB_DIR/pemkot-xx"
APACHE_PORT_WP="8000"
APACHE_PORT_GOV="8080"
WP_DB_NAME="wordpress_vuln"
WP_DB_USER="wp_user"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Log file
LOG_FILE="/tmp/cleanup_master.log"

echo -e "${BLUE}=== CLEANUP MASTER - INTEGRATED CLEANUP SOLUTION ===${NC}"

# Reset log file
> "$LOG_FILE"

# Fungsi logging
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log_message "INFO" "$1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log_message "SUCCESS" "$1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log_message "WARNING" "$1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log_message "ERROR" "$1"
}

# Fungsi untuk mengecek apakah user adalah root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Script ini harus dijalankan sebagai root"
        exit 1
    fi
}

# Fungsi untuk backup sebelum cleanup
backup_before_cleanup() {
    log_info "Membuat backup sebelum cleanup"
    
    local backup_dir="/tmp/vulnerable_web_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup WordPress files
    if [ -d "$WP_DIR" ]; then
        log_info "Backup WordPress files"
        cp -r "$WP_DIR" "$backup_dir/"
        log_success "WordPress files di-backup ke: $backup_dir/wordpress"
    fi
    
    # Backup Government website files
    if [ -d "$GOV_DIR" ]; then
        log_info "Backup Government website files"
        cp -r "$GOV_DIR" "$backup_dir/"
        log_success "Government website files di-backup ke: $backup_dir/pemkot-xx"
    fi
    
    # Backup database
    if command -v mysql >/dev/null 2>&1; then
        log_info "Backup database"
        mysqldump -u "$WP_DB_USER" -p"wp_pass123" "$WP_DB_NAME" > "$backup_dir/database_backup.sql" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_success "Database di-backup ke: $backup_dir/database_backup.sql"
        else
            log_warning "Gagal backup database"
        fi
    fi
    
    # Backup Apache configuration
    if [ -f "/etc/apache2/sites-available/wordpress-vuln.conf" ]; then
        log_info "Backup Apache configuration"
        cp /etc/apache2/sites-available/wordpress-vuln.conf "$backup_dir/"
        cp /etc/apache2/sites-available/pemkot-xx.conf "$backup_dir/"
        log_success "Apache configuration di-backup"
    fi
    
    log_success "Backup selesai di: $backup_dir"
}

# Fungsi untuk stop services
stop_services() {
    log_info "Menghentikan services"
    
    # Stop Apache
    if systemctl is-active --quiet apache2; then
        log_info "Menghentikan Apache"
        systemctl stop apache2
        log_success "Apache dihentikan"
    fi
    
    # Stop MySQL
    if systemctl is-active --quiet mysql; then
        log_info "Menghentikan MySQL"
        systemctl stop mysql
        log_success "MySQL dihentikan"
    fi
}

# Fungsi untuk hapus website files
remove_website_files() {
    log_info "Menghapus website files"
    
    # Hapus WordPress files
    if [ -d "$WP_DIR" ]; then
        log_info "Menghapus direktori WordPress: $WP_DIR"
        rm -rf "$WP_DIR"
        log_success "WordPress files dihapus"
    else
        log_warning "Direktori WordPress tidak ditemukan: $WP_DIR"
    fi
    
    # Hapus Government website files
    if [ -d "$GOV_DIR" ]; then
        log_info "Menghapus direktori Government website: $GOV_DIR"
        rm -rf "$GOV_DIR"
        log_success "Government website files dihapus"
    else
        log_warning "Direktori Government website tidak ditemukan: $GOV_DIR"
    fi
}

# Fungsi untuk hapus database
remove_database() {
    log_info "Menghapus database"
    
    if command -v mysql >/dev/null 2>&1; then
        # Start MySQL jika belum running
        if ! systemctl is-active --quiet mysql; then
            log_info "Menjalankan MySQL untuk cleanup database"
            systemctl start mysql
        fi
        
        # Drop database
        log_info "Menghapus database: $WP_DB_NAME"
        mysql -u root -e "DROP DATABASE IF EXISTS $WP_DB_NAME;" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_success "Database $WP_DB_NAME dihapus"
        else
            log_warning "Gagal menghapus database $WP_DB_NAME"
        fi
        
        # Drop user
        log_info "Menghapus database user: $WP_DB_USER"
        mysql -u root -e "DROP USER IF EXISTS '$WP_DB_USER'@'localhost';" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_success "Database user $WP_DB_USER dihapus"
        else
            log_warning "Gagal menghapus database user $WP_DB_USER"
        fi
        
        # Flush privileges
        mysql -u root -e "FLUSH PRIVILEGES;" 2>/dev/null
    else
        log_warning "MySQL tidak ditemukan"
    fi
}

# Fungsi untuk restore Apache configuration
restore_apache_config() {
    log_info "Mengembalikan konfigurasi Apache"
    
    # Disable vulnerable sites
    if [ -f "/etc/apache2/sites-enabled/wordpress-vuln" ]; then
        log_info "Disable WordPress vulnerable site"
        a2dissite wordpress-vuln
        log_success "WordPress vulnerable site disabled"
    fi
    
    if [ -f "/etc/apache2/sites-enabled/pemkot-xx" ]; then
        log_info "Disable Government website site"
        a2dissite pemkot-xx
        log_success "Government website site disabled"
    fi
    
    # Restore default site
    if [ -f "/etc/apache2/sites-available/000-default.conf.backup" ]; then
        log_info "Restore default Apache configuration"
        cp /etc/apache2/sites-available/000-default.conf.backup /etc/apache2/sites-available/000-default.conf
        a2ensite 000-default
        log_success "Default Apache configuration restored"
    fi
    
    # Restore ports.conf
    cat > /etc/apache2/ports.conf << EOF
Listen 80

<IfModule ssl_module>
        Listen 443
</IfModule>

<IfModule mod_gnutls.c>
        Listen 443
</IfModule>
EOF
    log_success "Ports configuration restored to default"
    
    # Remove vulnerable site configurations
    if [ -f "/etc/apache2/sites-available/wordpress-vuln.conf" ]; then
        log_info "Menghapus konfigurasi WordPress vulnerable site"
        rm -f /etc/apache2/sites-available/wordpress-vuln.conf
        log_success "WordPress vulnerable site configuration dihapus"
    fi
    
    if [ -f "/etc/apache2/sites-available/pemkot-xx.conf" ]; then
        log_info "Menghapus konfigurasi Government website site"
        rm -f /etc/apache2/sites-available/pemkot-xx.conf
        log_success "Government website site configuration dihapus"
    fi
}

# Fungsi untuk hapus logs
remove_logs() {
    log_info "Menghapus log files"
    
    # Remove Apache logs for vulnerable sites
    local log_files=(
        "/var/log/apache2/wordpress-vuln_access.log"
        "/var/log/apache2/wordpress-vuln_error.log"
        "/var/log/apache2/pemkot-xx_access.log"
        "/var/log/apache2/pemkot-xx_error.log"
    )
    
    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            log_info "Menghapus log file: $log_file"
            rm -f "$log_file"
            log_success "Log file dihapus: $log_file"
        fi
    done
}

# Fungsi untuk hapus temporary files
remove_temp_files() {
    log_info "Menghapus temporary files"
    
    # Remove WordPress temporary files
    rm -f /tmp/wordpress.tar.gz
    rm -f /tmp/contact-form-7-vuln.zip
    rm -rf /tmp/wordpress
    
    # Remove test files
    rm -rf /tmp/vuln_pentest
    rm -f /tmp/vulnerability_test.log
    rm -f /tmp/vulnerability_report.txt
    rm -f /tmp/vuln_pentest.log
    rm -f /tmp/vuln_pentest_report.txt
    
    log_success "Temporary files dihapus"
}

# Fungsi untuk restart services
restart_services() {
    log_info "Restart services"
    
    # Restart Apache
    log_info "Restart Apache"
    systemctl restart apache2
    if systemctl is-active --quiet apache2; then
        log_success "Apache berhasil di-restart"
    else
        log_error "Gagal restart Apache"
    fi
    
    # Restart MySQL
    log_info "Restart MySQL"
    systemctl restart mysql
    if systemctl is-active --quiet mysql; then
        log_success "MySQL berhasil di-restart"
    else
        log_error "Gagal restart MySQL"
    fi
}

# Fungsi untuk verifikasi cleanup
verify_cleanup() {
    log_info "Verifikasi cleanup"
    
    local issues=0
    
    # Check WordPress directory
    if [ -d "$WP_DIR" ]; then
        log_error "WordPress directory masih ada: $WP_DIR"
        ((issues++))
    else
        log_success "WordPress directory berhasil dihapus"
    fi
    
    # Check Government website directory
    if [ -d "$GOV_DIR" ]; then
        log_error "Government website directory masih ada: $GOV_DIR"
        ((issues++))
    else
        log_success "Government website directory berhasil dihapus"
    fi
    
    # Check database
    if command -v mysql >/dev/null 2>&1; then
        if mysql -u root -e "USE $WP_DB_NAME;" 2>/dev/null; then
            log_error "Database masih ada: $WP_DB_NAME"
            ((issues++))
        else
            log_success "Database berhasil dihapus"
        fi
    fi
    
    # Check Apache configuration
    if [ -f "/etc/apache2/sites-available/wordpress-vuln.conf" ]; then
        log_error "WordPress vulnerable site configuration masih ada"
        ((issues++))
    else
        log_success "WordPress vulnerable site configuration berhasil dihapus"
    fi
    
    if [ -f "/etc/apache2/sites-available/pemkot-xx.conf" ]; then
        log_error "Government website site configuration masih ada"
        ((issues++))
    else
        log_success "Government website site configuration berhasil dihapus"
    fi
    
    # Check if Apache is running on vulnerable ports
    if netstat -tlnp 2>/dev/null | grep -q ":8000"; then
        log_error "Apache masih berjalan di port 8000"
        ((issues++))
    else
        log_success "Apache tidak berjalan di port 8000"
    fi
    
    if netstat -tlnp 2>/dev/null | grep -q ":8080"; then
        log_error "Apache masih berjalan di port 8080"
        ((issues++))
    else
        log_success "Apache tidak berjalan di port 8080"
    fi
    
    if [ $issues -eq 0 ]; then
        log_success "Cleanup berhasil - tidak ada masalah yang ditemukan"
        return 0
    else
        log_warning "Cleanup selesai dengan $issues masalah yang perlu ditangani manual"
        return 1
    fi
}

# Fungsi untuk menampilkan informasi cleanup
show_cleanup_info() {
    log_info "Menampilkan informasi cleanup"
    
    echo -e "\n${BLUE}=== CLEANUP MASTER - INTEGRATED CLEANUP SOLUTION ===${NC}"
    echo -e "${GREEN}✓${NC} WordPress files dihapus"
    echo -e "${GREEN}✓${NC} Government website files dihapus"
    echo -e "${GREEN}✓${NC} Database dihapus"
    echo -e "${GREEN}✓${NC} Apache configuration dikembalikan"
    echo -e "${GREEN}✓${NC} Log files dihapus"
    echo -e "${GREEN}✓${NC} Temporary files dihapus"
    echo -e "${GREEN}✓${NC} Services di-restart"
    echo -e "${BLUE}===============================================${NC}\n"
    
    echo -e "${YELLOW}CATATAN:${NC}"
    echo -e "- Backup tersimpan di: /tmp/vulnerable_web_backup_*"
    echo -e "- Apache sekarang berjalan di port 80 (default)"
    echo -e "- MySQL tetap terinstalasi untuk penggunaan lain"
    echo -e "- Log file cleanup: $LOG_FILE"
    echo -e ""
}

# Fungsi untuk cleanup manual jika diperlukan
manual_cleanup_instructions() {
    echo -e "\n${YELLOW}=== MANUAL CLEANUP INSTRUCTIONS ===${NC}"
    echo -e "Jika ada masalah dengan cleanup otomatis, lakukan manual:"
    echo -e ""
    echo -e "1. Hapus website files:"
    echo -e "   sudo rm -rf $WP_DIR"
    echo -e "   sudo rm -rf $GOV_DIR"
    echo -e ""
    echo -e "2. Hapus database:"
    echo -e "   sudo mysql -u root -e \"DROP DATABASE IF EXISTS $WP_DB_NAME;\""
    echo -e "   sudo mysql -u root -e \"DROP USER IF EXISTS '$WP_DB_USER'@'localhost';\""
    echo -e ""
    echo -e "3. Restore Apache configuration:"
    echo -e "   sudo a2dissite wordpress-vuln"
    echo -e "   sudo a2dissite pemkot-xx"
    echo -e "   sudo a2ensite 000-default"
    echo -e "   sudo systemctl restart apache2"
    echo -e ""
    echo -e "4. Hapus log files:"
    echo -e "   sudo rm -f /var/log/apache2/wordpress-vuln_*.log"
    echo -e "   sudo rm -f /var/log/apache2/pemkot-xx_*.log"
    echo -e ""
    echo -e "5. Hapus temporary files:"
    echo -e "   sudo rm -f /tmp/wordpress.tar.gz"
    echo -e "   sudo rm -f /tmp/contact-form-7-vuln.zip"
    echo -e "   sudo rm -rf /tmp/wordpress"
    echo -e "   sudo rm -rf /tmp/vuln_pentest"
    echo -e ""
}

# Main function
main() {
    echo -e "${BLUE}=== CLEANUP MASTER - INTEGRATED CLEANUP SOLUTION ===${NC}"
    echo -e "Script ini akan menghapus semua website vulnerable"
    echo -e "dan mengembalikan sistem ke kondisi sebelum instalasi"
    echo -e "${YELLOW}PERINGATAN: Backup akan dibuat sebelum cleanup!${NC}\n"
    
    # Cek root privileges
    check_root
    
    log_info "Memulai cleanup master"
    
    # Konfirmasi dari user
    echo -e "${YELLOW}Apakah Anda yakin ingin menghapus semua website vulnerable?${NC}"
    echo -e "Ini akan menghapus:"
    echo -e "- WordPress files di $WP_DIR"
    echo -e "- Government website files di $GOV_DIR"
    echo -e "- Database $WP_DB_NAME"
    echo -e "- Apache configuration untuk port $APACHE_PORT_WP dan $APACHE_PORT_GOV"
    echo -e "- Log files dan temporary files"
    echo -e ""
    read -p "Lanjutkan? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleanup dibatalkan oleh user"
        exit 0
    fi
    
    # Backup sebelum cleanup
    backup_before_cleanup
    
    # Stop services
    stop_services
    
    # Remove website files
    remove_website_files
    
    # Remove database
    remove_database
    
    # Restore Apache configuration
    restore_apache_config
    
    # Remove logs
    remove_logs
    
    # Remove temporary files
    remove_temp_files
    
    # Restart services
    restart_services
    
    # Verify cleanup
    verify_cleanup
    
    # Show cleanup info
    show_cleanup_info
    
    # Show manual cleanup instructions
    manual_cleanup_instructions
    
    log_success "Cleanup master selesai!"
    log_info "Log file tersedia di: $LOG_FILE"
    
    echo -e "\n${GREEN}Cleanup selesai! Sistem telah dikembalikan ke kondisi sebelum instalasi.${NC}"
}

# Jalankan main function
main "$@"
