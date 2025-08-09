#!/bin/bash

# =================================================================
# TESTING SCRIPT - INTEGRATED TESTING
# =================================================================
# Script untuk testing kerentanan yang sudah diimplementasi
# =================================================================

# Konfigurasi
WP_URL="http://localhost:8000"
GOV_URL="http://localhost:8080"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== TESTING SCRIPT - INTEGRATED TESTING ===${NC}"

# Test WordPress
echo -e "${BLUE}1. Testing WordPress Site...${NC}"
if curl -s "$WP_URL" > /dev/null; then
    echo -e "${GREEN}✓ WordPress site accessible${NC}"
    echo -e "   URL: $WP_URL"
    echo -e "   Admin: wordpress-victim / admin123"
else
    echo -e "${RED}✗ WordPress site tidak dapat diakses${NC}"
fi

# Test Government Website
echo -e "${BLUE}2. Testing Government Website...${NC}"
if curl -s "$GOV_URL" > /dev/null; then
    echo -e "${GREEN}✓ Government website accessible${NC}"
    echo -e "   URL: $GOV_URL"
    echo -e "   Admin: admin / admin123"
else
    echo -e "${RED}✗ Government website tidak dapat diakses${NC}"
fi

# Test vulnerabilities
echo -e "${BLUE}3. Testing Vulnerabilities...${NC}"

# Test file upload
echo -e "${YELLOW}   Testing file upload...${NC}"
if curl -s "$GOV_URL/upload.php" > /dev/null; then
    echo -e "${GREEN}   ✓ Upload page accessible${NC}"
else
    echo -e "${RED}   ✗ Upload page tidak dapat diakses${NC}"
fi

# Test admin panel
echo -e "${YELLOW}   Testing admin panel...${NC}"
if curl -s "$GOV_URL/admin/" > /dev/null; then
    echo -e "${GREEN}   ✓ Admin panel accessible${NC}"
else
    echo -e "${RED}   ✗ Admin panel tidak dapat diakses${NC}"
fi

# Test shell access
echo -e "${YELLOW}   Testing shell access...${NC}"
if curl -s "$GOV_URL/shell.php?key=admin123" > /dev/null; then
    echo -e "${GREEN}   ✓ Shell accessible${NC}"
else
    echo -e "${RED}   ✗ Shell tidak dapat diakses${NC}"
fi

# Test Contact Form 7
echo -e "${YELLOW}   Testing Contact Form 7...${NC}"
if curl -s "$WP_URL/wp-content/uploads/test-form.html" > /dev/null; then
    echo -e "${GREEN}   ✓ Contact Form 7 test page accessible${NC}"
else
    echo -e "${RED}   ✗ Contact Form 7 test page tidak dapat diakses${NC}"
fi

echo -e "${BLUE}4. Testing selesai!${NC}"
echo -e "${GREEN}✓ Semua test telah selesai${NC}"
