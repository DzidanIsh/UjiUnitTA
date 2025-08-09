#!/bin/bash

# =================================================================
# CLEANUP SCRIPT - INTEGRATED CLEANUP
# =================================================================
# Script untuk membersihkan sistem setelah testing
# =================================================================

# Konfigurasi
WEB_DIR="/var/www/html"
WP_DIR="$WEB_DIR/wordpress"
GOV_DIR="$WEB_DIR/pemkot-xx"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== CLEANUP SCRIPT - INTEGRATED CLEANUP ===${NC}"

# Cek root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Script ini harus dijalankan sebagai root${NC}"
    exit 1
fi

echo -e "${YELLOW}PERINGATAN: Script ini akan menghapus semua website vulnerable!${NC}"
read -p "Apakah Anda yakin ingin melanjutkan? (y/N): " confirm

if [[ $confirm != [yY] ]]; then
    echo -e "${RED}Cleanup dibatalkan.${NC}"
    exit 1
fi

echo -e "${BLUE}1. Menghapus website...${NC}"

# Hapus website
if [ -d "$WP_DIR" ]; then
    rm -rf "$WP_DIR"
    echo -e "${GREEN}✓ WordPress website dihapus${NC}"
else
    echo -e "${YELLOW}WordPress website tidak ditemukan${NC}"
fi

if [ -d "$GOV_DIR" ]; then
    rm -rf "$GOV_DIR"
    echo -e "${GREEN}✓ Government website dihapus${NC}"
else
    echo -e "${YELLOW}Government website tidak ditemukan${NC}"
fi

echo -e "${BLUE}2. Menghapus database...${NC}"

# Hapus database
mysql -e "DROP DATABASE IF EXISTS wordpress_vuln;" 2>/dev/null
mysql -e "DROP USER IF EXISTS wp_user@localhost;" 2>/dev/null
echo -e "${GREEN}✓ Database dan user dihapus${NC}"

echo -e "${BLUE}3. Restore Apache config...${NC}"

# Restore Apache config
if [ -f "/etc/apache2/sites-available/000-default.conf.backup" ]; then
    cp /etc/apache2/sites-available/000-default.conf.backup /etc/apache2/sites-available/000-default.conf
    echo -e "${GREEN}✓ Apache config di-restore${NC}"
else
    echo -e "${YELLOW}Apache backup tidak ditemukan${NC}"
fi

# Disable sites
a2dissite wordpress-vuln.conf 2>/dev/null
a2dissite pemkot-xx.conf 2>/dev/null
a2ensite 000-default.conf

# Remove port configurations
sed -i '/Listen 8000/d' /etc/apache2/ports.conf
sed -i '/Listen 8080/d' /etc/apache2/ports.conf

# Restart Apache
systemctl restart apache2
echo -e "${GREEN}✓ Apache di-restart${NC}"

echo -e "${BLUE}4. Membersihkan firewall...${NC}"

# Remove firewall rules
ufw delete allow 8000/tcp 2>/dev/null
ufw delete allow 8080/tcp 2>/dev/null
echo -e "${GREEN}✓ Firewall rules dihapus${NC}"

echo -e "${BLUE}5. Cleanup selesai!${NC}"
echo -e "${GREEN}✓ Semua website vulnerable telah dihapus${NC}"
echo -e "${GREEN}✓ Sistem telah dikembalikan ke kondisi awal${NC}"
