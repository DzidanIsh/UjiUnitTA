#!/bin/bash

# =================================================================
# VULNERABLE WEB MASTER - INTEGRATED SOLUTION
# =================================================================
# Script terintegrasi untuk membuat website vulnerable dengan kerentanan file upload
# =================================================================

# Konfigurasi
WEB_DIR="/var/www/html"
WP_DIR="$WEB_DIR/wordpress"
GOV_DIR="$WEB_DIR/pemkot-xx"
APACHE_PORT_WP="8000"
APACHE_PORT_GOV="8080"
WP_DB_NAME="wordpress_vuln"
WP_DB_USER="wp_user"
WP_DB_PASS="wp_pass123"
WP_ADMIN_USER="wordpress-victim"
WP_ADMIN_PASS="admin123"
GOV_ADMIN_USER="admin"
GOV_ADMIN_PASS="admin123"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== VULNERABLE WEB MASTER - INTEGRATED SOLUTION ===${NC}"

# Cek root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Script ini harus dijalankan sebagai root${NC}"
    exit 1
fi

# Install dependencies
echo -e "${BLUE}1. Menginstalasi dependencies...${NC}"
apt update
apt install -y apache2 php php-mysql mysql-server wget curl unzip

# Configure Apache multi-site
echo -e "${BLUE}2. Mengkonfigurasi Apache multi-site...${NC}"

# Backup konfigurasi default
cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf.backup

# Buat konfigurasi untuk WordPress (port 8000)
cat > /etc/apache2/sites-available/wordpress-vuln.conf << EOF
<VirtualHost *:$APACHE_PORT_WP>
    ServerName vulnerable-wordpress.local
    ServerAdmin webmaster@vulnerable-wordpress.local
    DocumentRoot $WP_DIR
    
    <Directory $WP_DIR>
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog \${APACHE_LOG_DIR}/wordpress-vuln_error.log
    CustomLog \${APACHE_LOG_DIR}/wordpress-vuln_access.log combined
    
    <Directory $WP_DIR/wp-content/uploads>
        Options +ExecCGI +Indexes
        AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Buat konfigurasi untuk Government Website (port 8080)
cat > /etc/apache2/sites-available/pemkot-xx.conf << EOF
<VirtualHost *:$APACHE_PORT_GOV>
    ServerName pemkot-xx.go.id
    ServerAdmin webmaster@pemkot-xx.go.id
    DocumentRoot $GOV_DIR
    
    <Directory $GOV_DIR>
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog \${APACHE_LOG_DIR}/pemkot-xx_error.log
    CustomLog \${APACHE_LOG_DIR}/pemkot-xx_access.log combined
    
    <Directory $GOV_DIR/uploads>
        Options +ExecCGI +Indexes
        AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
        AllowOverride None
        Require all granted
    </Directory>
    
    <Directory $GOV_DIR/admin/uploads>
        Options +ExecCGI +Indexes
        AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF

# Enable sites dan ports
echo -e "${BLUE}3. Mengaktifkan sites dan ports...${NC}"
a2ensite wordpress-vuln.conf
a2ensite pemkot-xx.conf
a2dissite 000-default.conf

# Enable required modules
a2enmod rewrite
a2enmod headers
a2enmod cgi

# Configure ports
echo "Listen $APACHE_PORT_WP" >> /etc/apache2/ports.conf
echo "Listen $APACHE_PORT_GOV" >> /etc/apache2/ports.conf

# Restart Apache
systemctl restart apache2

# Setup MySQL
echo -e "${BLUE}4. Setup MySQL...${NC}"
systemctl start mysql
systemctl enable mysql

# Buat database WordPress
mysql -e "CREATE DATABASE IF NOT EXISTS $WP_DB_NAME;"
mysql -e "CREATE USER IF NOT EXISTS '$WP_DB_USER'@'localhost' IDENTIFIED BY '$WP_DB_PASS';"
mysql -e "GRANT ALL PRIVILEGES ON $WP_DB_NAME.* TO '$WP_DB_USER'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# Download dan setup WordPress
echo -e "${BLUE}5. Setup WordPress...${NC}"
cd /tmp
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
mv wordpress $WP_DIR

# Install WP-CLI
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
mv wp-cli.phar /usr/local/bin/wp

# Setup WordPress
cd $WP_DIR
wp core install --url="http://localhost:$APACHE_PORT_WP" --title="Vulnerable WordPress Site" --admin_user="$WP_ADMIN_USER" --admin_password="$WP_ADMIN_PASS" --admin_email="admin@vulnerable-site.local" --skip-email --allow-root 2>/dev/null

# Install Contact Form 7
wp plugin install contact-form-7 --activate --allow-root 2>/dev/null

# Buat kerentanan file upload WordPress Contact Form 7
echo -e "${BLUE}6. Membuat kerentanan Contact Form 7...${NC}"

# Buat .htaccess untuk uploads directory
cat > $WP_DIR/wp-content/uploads/.htaccess << EOF
Options +ExecCGI +Indexes
AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
<FilesMatch "\.(php|pl|py|jsp|asp|sh|cgi)$">
    SetHandler cgi-script
</FilesMatch>
DirectoryIndex index.php index.html
EOF

# Buat vulnerable Contact Form 7 template
cat > $WP_DIR/wp-content/plugins/contact-form-7/includes/submission.php.backup << EOF
# Backup file asli
EOF

# Buat vulnerable version dengan arbitrary file upload
cat > $WP_DIR/wp-content/plugins/contact-form-7/includes/submission.php << 'EOF'
<?php
// VULNERABLE CONTACT FORM 7 - Untuk testing keamanan
// PERINGATAN: JANGAN gunakan di lingkungan produksi!

// ... existing code ...

// Vulnerable file upload handler
if (isset($_FILES['file_upload']) && $_FILES['file_upload']['error'] === UPLOAD_ERR_OK) {
    $upload_dir = wp_upload_dir();
    $target_dir = $upload_dir['basedir'] . '/uploads/';
    
    // No file type validation - VULNERABLE
    $filename = $_FILES['file_upload']['name'];
    $target_file = $target_dir . $filename;
    
    if (move_uploaded_file($_FILES['file_upload']['tmp_name'], $target_file)) {
        // File uploaded successfully - can be executed
        $response['file_uploaded'] = $filename;
        $response['file_path'] = $target_file;
    }
}

// ... rest of existing code ...
EOF

# Buat test form dengan file upload
cat > $WP_DIR/wp-content/uploads/test-form.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Contact Form 7 Test</title>
</head>
<body>
    <h2>Contact Form 7 File Upload Test</h2>
    <form action="/wp-admin/admin-ajax.php" method="post" enctype="multipart/form-data">
        <input type="hidden" name="action" value="contact_form_7_upload">
        <input type="file" name="file_upload" required>
        <input type="submit" value="Upload File">
    </form>
    
    <h3>Testing Instructions:</h3>
    <ol>
        <li>Upload file PHP (shell.php, backdoor.php)</li>
        <li>Upload file executable (.sh, .py, .pl)</li>
        <li>File akan disimpan di /wp-content/uploads/</li>
        <li>File dapat dieksekusi langsung</li>
    </ol>
    
    <h3>Vulnerabilities:</h3>
    <ul>
        <li>No file type validation</li>
        <li>No file size limit</li>
        <li>Direct file execution</li>
        <li>Arbitrary file upload</li>
    </ul>
</body>
</html>
EOF

# Create Government Website
echo -e "${BLUE}7. Membuat website pemerintahan...${NC}"
mkdir -p $GOV_DIR/{uploads,admin,admin/uploads,assets/{css,js,images},public/documents}

# Copy existing HTML files
cp government_website_enhanced.html $GOV_DIR/index.html
cp admin_panel_enhanced.html $GOV_DIR/admin/login.html

# Copy integrated PHP files yang sudah dibuat
cp index.php $GOV_DIR/
cp admin_login.php $GOV_DIR/admin/
cp admin_panel.php $GOV_DIR/admin/
cp upload.php $GOV_DIR/
cp shell.php $GOV_DIR/
cp .htaccess $GOV_DIR/
cp sensitive-info.txt $GOV_DIR/

# Create .htaccess for uploads directory
cat > $GOV_DIR/uploads/.htaccess << 'EOF'
Options +ExecCGI +Indexes
AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
<FilesMatch "\.(php|pl|py|jsp|asp|sh|cgi)$">
    SetHandler cgi-script
</FilesMatch>
DirectoryIndex index.php index.html
EOF

# Create .htaccess for admin uploads directory
cat > $GOV_DIR/admin/uploads/.htaccess << 'EOF'
Options +ExecCGI +Indexes
AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
<FilesMatch "\.(php|pl|py|jsp|asp|sh|cgi)$">
    SetHandler cgi-script
</FilesMatch>
DirectoryIndex index.php index.html
EOF

# Set permissions
echo -e "${BLUE}8. Mengatur permissions...${NC}"
chown -R www-data:www-data $GOV_DIR
chown -R www-data:www-data $WP_DIR
chmod -R 755 $GOV_DIR
chmod -R 755 $WP_DIR
chmod -R 777 $GOV_DIR/uploads
chmod -R 777 $GOV_DIR/admin/uploads
chmod -R 777 $WP_DIR/wp-content/uploads

# Configure firewall
echo -e "${BLUE}9. Mengkonfigurasi firewall...${NC}"
ufw allow $APACHE_PORT_WP/tcp
ufw allow $APACHE_PORT_GOV/tcp
ufw allow 80/tcp
ufw allow 22/tcp

# Create sensitive info files
cat > $WP_DIR/sensitive-info.txt << EOF
=== INFORMASI SENSITIVE WORDPRESS ===
Website: Vulnerable WordPress Site
Database Name: $WP_DB_NAME
Database User: $WP_DB_USER
Database Password: $WP_DB_PASS
Admin Username: $WP_ADMIN_USER
Admin Password: $WP_ADMIN_PASS
Upload Directory: $WP_DIR/wp-content/uploads
Apache Port: $APACHE_PORT_WP

=== CONTACT FORM 7 VULNERABILITIES ===
Plugin: Contact Form 7 v5.7.3
Vulnerability: Arbitrary File Upload
File: /wp-content/plugins/contact-form-7/includes/submission.php
Risk: CRITICAL
Description: File upload tanpa validasi tipe file
Testing: Upload file PHP/executable via form

=== TESTING INSTRUCTIONS ===
1. Upload file via Contact Form 7
2. File akan disimpan di uploads/
3. File dapat dieksekusi langsung
4. Test dengan shell.php, backdoor.php
========================
EOF

cat > $GOV_DIR/sensitive-info.txt << EOF
=== INFORMASI SENSITIVE PEMKOT XX ===
Website: Pemerintah Kota XX
Admin Username: $GOV_ADMIN_USER
Admin Password: $GOV_ADMIN_PASS
Upload Directory: $GOV_DIR/uploads
Admin Upload Directory: $GOV_DIR/admin/uploads
Apache Port: $APACHE_PORT_GOV

=== VULNERABILITIES IMPLEMENTED ===
1. Unrestricted File Upload
2. File Execution via .htaccess
3. Directory Listing
4. Weak Authentication
5. PHP Shell Access
6. Information Disclosure

=== TESTING INSTRUCTIONS ===
1. Upload file via /upload.php
2. Admin panel: /admin/
3. Shell access: /shell.php?key=admin123
4. Directory browsing: /uploads/
========================
EOF

# Cleanup temporary files
rm -f /tmp/latest.tar.gz
rm -rf /tmp/wordpress

echo -e "${GREEN}✓${NC} Instalasi selesai!"
echo ""
echo -e "${BLUE}=== INFORMASI WEBSITE ===${NC}"
echo -e "${GREEN}WordPress Vulnerable Site:${NC}"
echo -e "   URL: http://localhost:$APACHE_PORT_WP"
echo -e "   Admin: $WP_ADMIN_USER / $WP_ADMIN_PASS"
echo -e "   Login: http://localhost:$APACHE_PORT_WP/wp-login.php"
echo -e "   Upload: $WP_DIR/wp-content/uploads"
echo -e "   Contact Form 7: Vulnerable to file upload"
echo -e ""
echo -e "${GREEN}Government Website:${NC}"
echo -e "   URL: http://localhost:$APACHE_PORT_GOV"
echo -e "   Admin: $GOV_ADMIN_USER / $GOV_ADMIN_PASS"
echo -e "   Admin Panel: http://localhost:$APACHE_PORT_GOV/admin/"
echo -e "   Upload: http://localhost:$APACHE_PORT_GOV/upload.php"
echo -e "   Upload Directory: $GOV_DIR/uploads"
echo -e ""
echo -e "${GREEN}Kerentanan yang Diimplementasi:${NC}"
echo -e "   - Unrestricted File Upload (Government Site)"
echo -e "   - Arbitrary File Upload (WordPress Contact Form 7)"
echo -e "   - File Execution via .htaccess"
echo -e "   - Directory Listing"
echo -e "   - Weak Authentication"
echo -e "   - PHP Shell Access"
echo -e ""
echo -e "${YELLOW}PERINGATAN: Website ini dibuat untuk testing keamanan!${NC}"

# =================================================================
# DOKUMENTASI PENGGUNAAN SCRIPT
# =================================================================

echo ""
echo -e "${BLUE}=== DOKUMENTASI PENGGUNAAN ===${NC}"
echo ""
echo -e "${GREEN}1. CARA MENJALANKAN SCRIPT:${NC}"
echo -e "   sudo bash vuln_web_master.sh"
echo -e "   atau"
echo -e "   sudo ./vuln_web_master.sh"
echo ""
echo -e "${GREEN}2. PERSYARATAN SISTEM:${NC}"
echo -e "   - Ubuntu/Debian Linux (root privileges)"
echo -e "   - Koneksi internet untuk download dependencies"
echo -e "   - Minimal 2GB RAM dan 10GB disk space"
echo -e "   - Port 8000, 8080, dan 80 harus tersedia"
echo ""
echo -e "${GREEN}3. FITUR YANG DIBUAT:${NC}"
echo -e "   A. WORDPRESS VULNERABLE SITE (Port 8000):"
echo -e "      - Website WordPress lengkap dengan database"
echo -e "      - Plugin Contact Form 7 terinstall"
echo -e "      - Upload directory dengan eksekusi file"
echo -e "      - Admin panel: wordpress-victim / admin123"
echo -e ""
echo -e "   B. GOVERNMENT WEBSITE (Port 8080):"
echo -e "      - Website pemerintahan dengan Bootstrap UI"
echo -e "      - Admin panel: admin / admin123"
echo -e "      - File upload tanpa validasi"
echo -e "      - Directory listing aktif"
echo -e "      - Shell PHP untuk testing"
echo ""
echo -e "${GREEN}4. KERENTANAN YANG DIIMPLEMENTASI:${NC}"
echo -e "   - Unrestricted File Upload (tidak ada validasi tipe file)"
echo -e "   - File Execution via .htaccess (eksekusi file PHP/script)"
echo -e "   - Directory Listing (browsing direktori)"
echo -e "   - Weak Authentication (password sederhana)"
echo -e "   - Missing Input Validation (tidak ada sanitasi input)"
echo -e "   - Information Disclosure (file sensitive-info.txt)"
echo ""
echo -e "${GREEN}5. CARA TESTING KERENTANAN:${NC}"
echo -e "   A. File Upload Vulnerability:"
echo -e "      - Upload file PHP (shell.php, backdoor.php)"
echo -e "      - Upload file executable (.sh, .py, .pl)"
echo -e "      - Akses file yang diupload via browser"
echo -e ""
echo -e "   B. Directory Traversal:"
echo -e "      - Akses: http://localhost:8080/uploads/"
echo -e "      - Akses: http://localhost:8000/wp-content/uploads/"
echo -e ""
echo -e "   C. Authentication Bypass:"
echo -e "      - Coba login dengan kredensial default"
echo -e "      - Test SQL injection pada form login"
echo -e ""
echo -e "   D. Information Disclosure:"
echo -e "      - Baca file sensitive-info.txt"
echo -e "      - Akses error logs Apache"
echo -e "      - View source code PHP"
echo ""
echo -e "${GREEN}6. SCENARIO TESTING:${NC}"
echo -e "   A. Penetration Testing:"
echo -e "      - Reconnaissance: port scanning, directory discovery"
echo -e "      - Vulnerability Assessment: file upload, authentication"
echo -e "      - Exploitation: shell upload, command execution"
echo -e "      - Post-exploitation: privilege escalation, data exfiltration"
echo -e ""
echo -e "   B. Incident Response Training:"
echo -e "      - Deteksi serangan file upload"
echo -e "      - Analisis log Apache dan sistem"
echo -e "      - Containment dan eradication"
echo -e "      - Recovery dan hardening"
echo ""
echo -e "${GREEN}7. MONITORING DAN LOGGING:${NC}"
echo -e "   - Apache Access Log: /var/log/apache2/wordpress-vuln_access.log"
echo -e "   - Apache Error Log: /var/log/apache2/wordpress-vuln_error.log"
echo -e "   - System Log: /var/log/syslog"
echo -e "   - MySQL Log: /var/log/mysql/error.log"
echo ""
echo -e "${GREEN}8. KEAMANAN DAN BEST PRACTICES:${NC}"
echo -e "   - JANGAN gunakan di production environment"
echo -e "   - JANGAN expose ke internet publik"
echo -e "   - SELALU gunakan dalam environment yang terisolasi"
echo -e "   - MONITOR aktivitas dan log secara berkala"
echo -e "   - BACKUP data sebelum testing"
echo -e "   - DOCUMENT semua aktivitas testing"
echo ""
echo -e "${GREEN}9. TROUBLESHOOTING:${NC}"
echo -e "   A. Apache tidak start:"
echo -e "      - Cek port conflicts: sudo netstat -tlnp | grep :80"
echo -e "      - Restart service: sudo systemctl restart apache2"
echo -e "      - Cek error log: sudo tail -f /var/log/apache2/error.log"
echo -e ""
echo -e "   B. MySQL connection error:"
echo -e "      - Start MySQL: sudo systemctl start mysql"
echo -e "      - Reset password: sudo mysql_secure_installation"
echo -e "      - Cek status: sudo systemctl status mysql"
echo -e ""
echo -e "   C. Permission denied:"
echo -e "      - Set ownership: sudo chown -R www-data:www-data /var/www/html"
echo -e "      - Set permissions: sudo chmod -R 755 /var/www/html"
echo -e ""
echo -e "${GREEN}10. CLEANUP DAN UNINSTALL:${NC}"
echo -e "   A. Hapus website:"
echo -e "      - sudo rm -rf /var/www/html/wordpress"
echo -e "      - sudo rm -rf /var/www/html/pemkot-xx"
echo -e ""
echo -e "   B. Hapus database:"
echo -e "      - sudo mysql -u root -e 'DROP DATABASE wordpress_vuln;'"
echo -e "      - sudo mysql -u root -e 'DROP USER wp_user@localhost;'"
echo -e ""
echo -e "   C. Restore Apache config:"
echo -e "      - sudo cp /etc/apache2/sites-available/000-default.conf.backup /etc/apache2/sites-available/000-default.conf"
echo -e "      - sudo a2ensite 000-default"
echo -e "      - sudo a2dissite wordpress-vuln pemkot-xx"
echo -e "      - sudo systemctl restart apache2"
echo ""
echo -e "${GREEN}11. INTEGRASI DENGAN TOOLS LAIN:${NC}"
echo -e "   - Nmap: port scanning dan service detection"
echo -e "   - Nikto: web vulnerability scanner"
echo -e "   - OWASP ZAP: automated security testing"
echo -e "   - Burp Suite: manual security testing"
echo -e "   - Metasploit: exploitation framework"
echo -e "   - Wireshark: network traffic analysis"
echo ""
echo -e "${GREEN}12. REPORTING DAN DOCUMENTATION:${NC}"
echo -e "   - Dokumentasikan semua temuan kerentanan"
echo -e "      - Severity level (Critical, High, Medium, Low, Info)"
echo -e "      - CVSS score dan vector"
echo -e "      - Proof of concept"
echo -e "      - Impact assessment"
echo -e "      - Remediation steps"
echo -e "      - Timeline discovery dan remediation"
echo ""
echo -e "${GREEN}13. COMPLIANCE DAN STANDARDS:${NC}"
echo -e "   - OWASP Top 10 2021"
echo -e "   - NIST Cybersecurity Framework"
echo -e "   - ISO 27001 Information Security"
echo -e "   - PCI DSS (jika applicable)"
echo -e "   - GDPR (jika applicable)"
echo ""
echo -e "${GREEN}14. LEGAL DAN ETIKA:${NC}"
echo -e "   - SELALU dapatkan izin tertulis sebelum testing"
echo -e "   - JANGAN test sistem tanpa authorization"
echo -e "   - RESPECT privacy dan confidentiality"
echo -e "   - DOCUMENT semua aktivitas testing"
echo -e "   - REPORT temuan sesuai kebijakan organisasi"
echo ""
echo -e "${GREEN}15. CONTINUOUS IMPROVEMENT:${NC}"
echo -e "   - Update script secara berkala"
echo -e "   - Tambahkan kerentanan baru sesuai trend"
echo -e "   - Improve detection dan monitoring"
echo -e "   - Share knowledge dengan komunitas"
echo -e "   - Participate dalam bug bounty programs"
echo ""
echo -e "${BLUE}=== AKHIR DOKUMENTASI ===${NC}"
echo ""
echo -e "${YELLOW}Script siap digunakan untuk testing keamanan!${NC}"
echo -e "${YELLOW}Pastikan semua persyaratan terpenuhi sebelum menjalankan.${NC}"
echo ""
echo -e "${GREEN}Happy Security Testing! 🔒${NC}"
