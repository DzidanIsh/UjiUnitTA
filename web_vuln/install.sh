#!/bin/bash

# =================================================================
# VULNERABLE WEB SYSTEM - INTEGRATED INSTALLER
# =================================================================
# Script instalasi terintegrasi untuk sistem web vulnerable
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

echo -e "${BLUE}=== VULNERABLE WEB SYSTEM - INTEGRATED INSTALLER ===${NC}"

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
