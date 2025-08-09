#!/bin/bash

# =================================================================
# CONFIGURATION SCRIPT
# =================================================================
# Script untuk konfigurasi tambahan
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

echo -e "${BLUE}=== CONFIGURATION SCRIPT ===${NC}"

# Cek root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Script ini harus dijalankan sebagai root${NC}"
    exit 1
fi

echo -e "${BLUE}1. Mengatur permissions...${NC}"
chown -R www-data:www-data $GOV_DIR
chown -R www-data:www-data $WP_DIR
chmod -R 755 $GOV_DIR
chmod -R 755 $WP_DIR
chmod -R 777 $GOV_DIR/uploads
chmod -R 777 $GOV_DIR/admin/uploads
chmod -R 777 $WP_DIR/wp-content/uploads

echo -e "${BLUE}2. Restart services...${NC}"
systemctl restart apache2
systemctl restart mysql

echo -e "${BLUE}3. Konfigurasi selesai!${NC}"
echo -e "${GREEN}✓ Semua konfigurasi telah diterapkan${NC}"
