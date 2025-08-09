# Vulnerable Web System - Master Documentation

## Overview
Sistem terintegrasi untuk membuat website vulnerable dengan kerentanan file upload yang dapat digunakan untuk testing keamanan. Sistem ini mencakup WordPress dengan Contact Form 7 dan website pemerintahan dalam satu solusi yang mudah digunakan.

## 🎯 **Tujuan Utama**
- Website vulnerable dengan kerentanan file upload
- WordPress + Contact Form 7 (plugin vulnerable)
- Website pemerintahan dengan admin panel
- Single command installation dan testing
- Integrated penetration testing
- Complete cleanup solution

## 📁 **Struktur File Master**

### **Script Utama:**
- `vuln_web_master.sh` - Script instalasi terintegrasi
- `pentest_master.sh` - Script pentesting terintegrasi
- `cleanup_master.sh` - Script cleanup terintegrasi
- `setup_master.sh` - Script setup permissions

### **File yang Dihapus (Tidak Diperlukan):**
- `install_vulnerable_web.sh` (digabung ke vuln_web_master.sh)
- `gov_website.sh` (digabung ke vuln_web_master.sh)
- `create_gov_website.sh` (digabung ke vuln_web_master.sh)
- `pentest_gov_website.sh` (digabung ke pentest_master.sh)
- `cleanup_vulnerable_web.sh` (digabung ke cleanup_master.sh)
- `setup_gov_permissions.sh` (digabung ke setup_master.sh)
- `setup_permissions.sh` (digabung ke setup_master.sh)
- `test_vulnerabilities.sh` (digabung ke pentest_master.sh)
- `troubleshoot_wordpress.sh` (tidak diperlukan)
- `setupnetworkvulweb.sh` (tidak diperlukan)

## 🚀 **Cara Penggunaan**

### **1. Setup Permissions**
```bash
chmod +x setup_master.sh
./setup_master.sh
```

### **2. Install System**
```bash
sudo ./vuln_web_master.sh
```

### **3. Run Penetration Testing**
```bash
./pentest_master.sh
```

### **4. Cleanup System**
```bash
sudo ./cleanup_master.sh
```

## 🌐 **Website yang Dibuat**

### **1. WordPress Vulnerable Site**
- **URL**: http://localhost:8000
- **Admin**: wordpress-victim / admin123
- **Login**: http://localhost:8000/wp-login.php
- **Upload Directory**: /var/www/html/wordpress/wp-content/uploads
- **Plugin**: Contact Form 7 (vulnerable)

### **2. Government Website**
- **URL**: http://localhost:8080
- **Admin**: admin / admin123
- **Admin Panel**: http://localhost:8080/admin/
- **Upload Page**: http://localhost:8080/upload.php
- **Upload Directory**: /var/www/html/pemkot-xx/uploads

## 🔍 **Kerentanan yang Diimplementasi**

### **1. Unrestricted File Upload**
```php
// Tidak ada validasi tipe file
if ($file['error'] === UPLOAD_ERR_OK) {
    $filename = $file['name'];
    $destination = $upload_dir . $filename;
    move_uploaded_file($file['tmp_name'], $destination);
}
```

### **2. File Execution**
```apache
# .htaccess untuk mengizinkan eksekusi file
Options +ExecCGI +Indexes
AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
<FilesMatch "\.(php|pl|py|jsp|asp|sh|cgi)$">
    SetHandler cgi-script
</FilesMatch>
```

### **3. Directory Listing**
```apache
# Directory listing diaktifkan
Options +Indexes
```

### **4. Weak Authentication**
```php
// Simple authentication tanpa database
if ($_POST['username'] === 'admin' && $_POST['password'] === 'admin123') {
    $_SESSION['admin'] = true;
}
```

### **5. Contact Form 7 Vulnerabilities**
- File upload vulnerability
- XSS vulnerability
- Unrestricted file type upload

## 🧪 **Testing Scenarios**

### **Scenario 1: WordPress File Upload Attack**
1. Upload PHP shell via Contact Form 7
2. Access shell via browser
3. Execute system commands
4. Gain server access

### **Scenario 2: Government Website Compromise**
1. Access admin panel
2. Login with default credentials
3. Upload malicious file
4. Execute commands via shell

### **Scenario 3: Information Gathering**
1. Browse directory listings
2. Access sensitive files
3. Gather system information
4. Map application structure

## 📊 **Pentesting Coverage**

Script `pentest_master.sh` mencakup:
- ✅ Website availability testing
- ✅ Directory listing testing
- ✅ File upload vulnerability testing
- ✅ Admin panel testing
- ✅ Sensitive files access testing
- ✅ Shell access testing
- ✅ SQL injection testing
- ✅ XSS testing
- ✅ Contact Form 7 vulnerability testing
- ✅ Comprehensive reporting

## 🔧 **Manual Testing Commands**

### **WordPress Testing**
```bash
# Test login page
curl "http://localhost:8000/wp-login.php"

# Test admin login
curl -X POST -d "log=wordpress-victim&pwd=admin123&wp-submit=Log+In" http://localhost:8000/wp-login.php

# Test Contact Form 7 upload
curl -X POST -F "file=@shell.php" http://localhost:8000/wp-content/plugins/contact-form-7/upload.php
```

### **Government Website Testing**
```bash
# Test admin panel
curl "http://localhost:8080/admin/"

# Test admin login
curl -X POST -d "username=admin&password=admin123" http://localhost:8080/admin/

# Test file upload
curl -X POST -F "file=@shell.php" http://localhost:8080/upload.php

# Test shell access
curl "http://localhost:8080/uploads/shell.php?cmd=whoami"
```

### **Directory Listing Testing**
```bash
# Test WordPress directories
curl "http://localhost:8000/wp-content/uploads/"
curl "http://localhost:8000/wp-content/plugins/"

# Test Government directories
curl "http://localhost:8080/uploads/"
curl "http://localhost:8080/admin/"
```

### **Sensitive Files Testing**
```bash
# Test WordPress sensitive files
curl "http://localhost:8000/sensitive-info.txt"
curl "http://localhost:8000/wp-config.php"

# Test Government sensitive files
curl "http://localhost:8080/sensitive-info.txt"
curl "http://localhost:8080/uploads/.htaccess"
```

## 🔒 **Security Recommendations**

### **1. File Upload Security**
```php
// Implementasi validasi file upload
$allowed_types = ['jpg', 'png', 'pdf', 'doc'];
$file_extension = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

if (!in_array($file_extension, $allowed_types)) {
    die('File type not allowed');
}

// Validasi MIME type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);

if (!in_array($mime_type, ['image/jpeg', 'image/png', 'application/pdf'])) {
    die('Invalid file type');
}
```

### **2. Directory Security**
```apache
# Disable directory listing
Options -Indexes

# Prevent file execution in uploads
<Directory /var/www/html/uploads>
    <FilesMatch "\.(php|pl|py|jsp|asp|sh|cgi)$">
        Deny from all
    </FilesMatch>
</Directory>
```

### **3. Authentication Security**
```php
// Use strong authentication
// Implement password hashing
// Use session management
// Implement rate limiting
```

### **4. Input Validation**
```php
// Sanitize all inputs
$input = htmlspecialchars($_POST['input'], ENT_QUOTES, 'UTF-8');
$input = filter_var($_POST['input'], FILTER_SANITIZE_STRING);
```

## 📈 **Monitoring dan Logging**

### **Apache Logs**
```bash
# WordPress logs
tail -f /var/log/apache2/wordpress-vuln_access.log
tail -f /var/log/apache2/wordpress-vuln_error.log

# Government website logs
tail -f /var/log/apache2/pemkot-xx_access.log
tail -f /var/log/apache2/pemkot-xx_error.log
```

### **File Monitoring**
```bash
# Monitor upload directories
watch -n 1 "ls -la /var/www/html/wordpress/wp-content/uploads/"
watch -n 1 "ls -la /var/www/html/pemkot-xx/uploads/"

# Monitor file changes
inotifywait -m /var/www/html/wordpress/wp-content/uploads/
inotifywait -m /var/www/html/pemkot-xx/uploads/
```

## 🗂️ **File Structure After Installation**

```
/var/www/html/
├── wordpress/                    # WordPress Vulnerable Site
│   ├── wp-content/
│   │   ├── uploads/             # Upload directory (vulnerable)
│   │   │   └── .htaccess        # File execution enabled
│   │   └── plugins/
│   │       └── contact-form-7/  # Vulnerable plugin
│   ├── wp-login.php             # Login page
│   ├── wp-admin/                # Admin panel
│   └── sensitive-info.txt       # Sensitive information
└── pemkot-xx/                   # Government Website
    ├── uploads/                 # Upload directory (vulnerable)
    │   ├── .htaccess            # File execution enabled
    │   └── shell.php            # Test shell
    ├── admin/                   # Admin panel
    │   ├── index.php            # Login page
    │   ├── upload.php           # Upload script
    │   └── logout.php           # Logout script
    ├── index.php                # Main page
    ├── upload.php               # Public upload
    └── sensitive-info.txt       # Sensitive information
```

## ⚠️ **Disclaimer**

**PERINGATAN KEAMANAN**
- Website ini **HANYA** untuk testing keamanan
- **JANGAN** gunakan di lingkungan produksi
- **JANGAN** expose ke internet publik
- **HAPUS** setelah selesai testing
- **GUNAKAN** hanya di lingkungan yang terkontrol

## 🔄 **Workflow Lengkap**

### **1. Preparation**
```bash
# Clone atau download script
cd web_vuln/
chmod +x setup_master.sh
./setup_master.sh
```

### **2. Installation**
```bash
sudo ./vuln_web_master.sh
```

### **3. Testing**
```bash
# Automated testing
./pentest_master.sh

# Manual testing
curl "http://localhost:8000"
curl "http://localhost:8080"
```

### **4. Cleanup**
```bash
sudo ./cleanup_master.sh
```

## 📋 **Checklist Testing**

- [ ] WordPress site accessible
- [ ] Government website accessible
- [ ] Admin panels accessible
- [ ] File upload working
- [ ] Directory listing enabled
- [ ] Shell access working
- [ ] Sensitive files accessible
- [ ] Contact Form 7 vulnerable
- [ ] SQL injection possible
- [ ] XSS vulnerability present

## 🎓 **Learning Objectives**

1. **File Upload Vulnerabilities**
   - Understanding unrestricted file upload
   - File type validation bypass
   - File execution via web server

2. **Web Application Security**
   - Directory listing exposure
   - Sensitive file disclosure
   - Weak authentication

3. **Penetration Testing**
   - Automated vulnerability scanning
   - Manual testing techniques
   - Report generation

4. **Incident Response**
   - Vulnerability identification
   - Risk assessment
   - Remediation planning

## 🆘 **Troubleshooting**

### **Common Issues:**
1. **Port already in use**: Change ports in script configuration
2. **Permission denied**: Run with sudo
3. **MySQL connection failed**: Check MySQL service status
4. **Apache not starting**: Check configuration files
5. **File upload not working**: Check directory permissions

### **Debug Commands:**
```bash
# Check service status
systemctl status apache2
systemctl status mysql

# Check port usage
netstat -tlnp | grep :8000
netstat -tlnp | grep :8080

# Check logs
tail -f /var/log/apache2/error.log
tail -f /var/log/mysql/error.log

# Check permissions
ls -la /var/www/html/
```

## 📞 **Support**

Jika mengalami masalah:
1. Cek log files Apache dan MySQL
2. Verifikasi permissions dan ownership
3. Test konektivitas dan port availability
4. Review konfigurasi script
5. Dokumentasikan error untuk analisis

---

**Sistem ini siap digunakan untuk testing keamanan, training security teams, dan validasi incident response procedures!**
