#!/bin/bash

# =================================================================
# MAIN SCRIPT - INTEGRATED SOLUTION
# =================================================================
# Script utama yang mengintegrasikan semua fungsi
# =================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== VULNERABLE WEB SYSTEM - MAIN SCRIPT ===${NC}"

# Function untuk menampilkan menu
show_menu() {
    echo ""
    echo -e "${BLUE}Pilih opsi:${NC}"
    echo -e "1. Install system"
    echo -e "2. Test vulnerabilities"
    echo -e "3. Configure system"
    echo -e "4. Cleanup system"
    echo -e "5. Show status"
    echo -e "6. Exit"
    echo ""
}

# Function untuk install
install_system() {
    echo -e "${BLUE}Installing system...${NC}"
    if [ -f "install.sh" ]; then
        sudo bash install.sh
    else
        echo -e "${RED}Install script tidak ditemukan!${NC}"
    fi
}

# Function untuk test
test_system() {
    echo -e "${BLUE}Testing system...${NC}"
    if [ -f "test.sh" ]; then
        sudo bash test.sh
    else
        echo -e "${RED}Test script tidak ditemukan!${NC}"
    fi
}

# Function untuk configure
configure_system() {
    echo -e "${BLUE}Configuring system...${NC}"
    if [ -f "config/setup.sh" ]; then
        sudo bash config/setup.sh
    else
        echo -e "${RED}Config script tidak ditemukan!${NC}"
    fi
}

# Function untuk cleanup
cleanup_system() {
    echo -e "${BLUE}Cleaning up system...${NC}"
    if [ -f "cleanup.sh" ]; then
        sudo bash cleanup.sh
    else
        echo -e "${RED}Cleanup script tidak ditemukan!${NC}"
    fi
}

# Function untuk show status
show_status() {
    echo -e "${BLUE}System Status:${NC}"
    
    # Check WordPress
    if curl -s "http://localhost:8000" > /dev/null; then
        echo -e "${GREEN}✓ WordPress: Running (Port 8000)${NC}"
    else
        echo -e "${RED}✗ WordPress: Not running${NC}"
    fi
    
    # Check Government Website
    if curl -s "http://localhost:8080" > /dev/null; then
        echo -e "${GREEN}✓ Government Website: Running (Port 8080)${NC}"
    else
        echo -e "${RED}✗ Government Website: Not running${NC}"
    fi
    
    # Check Apache
    if systemctl is-active --quiet apache2; then
        echo -e "${GREEN}✓ Apache: Running${NC}"
    else
        echo -e "${RED}✗ Apache: Not running${NC}"
    fi
    
    # Check MySQL
    if systemctl is-active --quiet mysql; then
        echo -e "${GREEN}✓ MySQL: Running${NC}"
    else
        echo -e "${RED}✗ MySQL: Not running${NC}"
    fi
}

# Main loop
while true; do
    show_menu
    read -p "Masukkan pilihan (1-6): " choice
    
    case $choice in
        1)
            install_system
            ;;
        2)
            test_system
            ;;
        3)
            configure_system
            ;;
        4)
            cleanup_system
            ;;
        5)
            show_status
            ;;
        6)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Pilihan tidak valid!${NC}"
            ;;
    esac
    
    echo ""
    read -p "Tekan Enter untuk melanjutkan..."
done
