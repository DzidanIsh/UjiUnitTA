#!/bin/bash

# =================================================================
# SETUP MASTER - PERMISSIONS SETUP
# =================================================================
# Script untuk memberikan permission execute pada semua script master
# =================================================================

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== SETUP MASTER - PERMISSIONS SETUP ===${NC}"
echo -e "Memberikan permission execute pada script master"
echo ""

# List of master scripts to make executable
scripts=(
    "vuln_web_master.sh"
    "pentest_master.sh"
    "cleanup_master.sh"
)

# Make scripts executable
for script in "${scripts[@]}"; do
    if [ -f "$script" ]; then
        chmod +x "$script"
        echo -e "${GREEN}✓${NC} $script - permission execute diberikan"
    else
        echo -e "${YELLOW}⚠${NC} $script - file tidak ditemukan"
    fi
done

echo ""
echo -e "${BLUE}=== USAGE INSTRUCTIONS ===${NC}"
echo -e "${GREEN}1. Install Vulnerable Web System:${NC}"
echo -e "   sudo ./vuln_web_master.sh"
echo ""
echo -e "${GREEN}2. Run Penetration Testing:${NC}"
echo -e "   ./pentest_master.sh"
echo ""
echo -e "${GREEN}3. Cleanup System:${NC}"
echo -e "   sudo ./cleanup_master.sh"
echo ""
echo -e "${GREEN}4. Manual Testing Commands:${NC}"
echo -e "   # WordPress Testing"
echo -e "   curl \"http://localhost:8000/wp-login.php\""
echo -e "   curl -X POST -d \"log=wordpress-victim&pwd=admin123&wp-submit=Log+In\" http://localhost:8000/wp-login.php"
echo -e ""
echo -e "   # Government Website Testing"
echo -e "   curl \"http://localhost:8080/admin/\""
echo -e "   curl -X POST -d \"username=admin&password=admin123\" http://localhost:8080/admin/"
echo -e "   curl -X POST -F \"file=@shell.php\" http://localhost:8080/upload.php"
echo -e ""
echo -e "   # Shell Access Testing"
echo -e "   curl \"http://localhost:8080/uploads/shell.php?cmd=whoami\""
echo -e ""
echo -e "${YELLOW}PERINGATAN:${NC} Website ini dibuat untuk testing keamanan!"
echo -e "${YELLOW}Jangan gunakan di lingkungan produksi!${NC}"
