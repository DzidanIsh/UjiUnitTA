<?php
// Get current page info
$current_page = basename($_SERVER['PHP_SELF']);
$upload_dir = 'uploads/';

// Get file count
$file_count = 0;
if (is_dir($upload_dir)) {
    $files = scandir($upload_dir);
    $file_count = count(array_filter($files, function($file) {
        return $file !== '.' && $file !== '..';
    }));
}

// Get system info
$system_info = [
    'PHP Version' => phpversion(),
    'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
    'Server OS' => php_uname('s'),
    'Server Hostname' => php_uname('n'),
    'Current Time' => date('Y-m-d H:i:s'),
    'Upload Directory' => $upload_dir,
    'Files Uploaded' => $file_count
];
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PEMERINTAH KOTA XX - Portal Resmi</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --primary-color: #1e3a8a;
            --secondary-color: #3b82f6;
            --accent-color: #f59e0b;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --light-color: #f8fafc;
            --dark-color: #1e293b;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
        }

        body {
            font-family: 'Poppins', sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background-color: var(--light-color);
        }

        /* Header Styles */
        .top-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 8px 0;
            font-size: 14px;
        }

        .top-header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .top-header a {
            color: white;
            text-decoration: none;
            margin-left: 20px;
        }

        .top-header a:hover {
            color: var(--accent-color);
        }

        .main-header {
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px 0;
        }

        .logo-section {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .logo-circle {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
            font-weight: bold;
        }

        .logo-text h1 {
            font-size: 24px;
            font-weight: 700;
            color: var(--primary-color);
            margin: 0;
        }

        .logo-text p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 14px;
        }

        .navbar-nav .nav-link {
            color: var(--text-primary);
            font-weight: 500;
            padding: 10px 20px;
            border-radius: 25px;
            transition: all 0.3s ease;
        }

        .navbar-nav .nav-link:hover,
        .navbar-nav .nav-link.active {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
        }

        /* Hero Section */
        .hero-section {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 80px 0;
            text-align: center;
        }

        .hero-title {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 20px;
        }

        .hero-subtitle {
            font-size: 1.2rem;
            margin-bottom: 40px;
            opacity: 0.9;
        }

        .hero-buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }

        .btn-hero {
            padding: 15px 30px;
            border-radius: 25px;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.3s ease;
        }

        .btn-hero.primary {
            background: white;
            color: var(--primary-color);
        }

        .btn-hero.primary:hover {
            background: var(--light-color);
            transform: translateY(-2px);
        }

        .btn-hero.secondary {
            background: transparent;
            color: white;
            border: 2px solid white;
        }

        .btn-hero.secondary:hover {
            background: white;
            color: var(--primary-color);
            transform: translateY(-2px);
        }

        /* Features Section */
        .features-section {
            padding: 80px 0;
            background: white;
        }

        .feature-card {
            background: white;
            border-radius: 20px;
            padding: 40px 30px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            height: 100%;
        }

        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 60px rgba(0,0,0,0.15);
        }

        .feature-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 32px;
            margin: 0 auto 30px;
        }

        .feature-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 15px;
        }

        .feature-description {
            color: var(--text-secondary);
            margin-bottom: 20px;
        }

        /* Vulnerability Warning */
        .vulnerability-warning {
            background: linear-gradient(135deg, var(--warning-color), #f97316);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin: 30px 0;
        }

        /* System Info */
        .system-info {
            background: var(--light-color);
            border-radius: 15px;
            padding: 25px;
            margin: 30px 0;
        }

        .system-info h5 {
            color: var(--primary-color);
            margin-bottom: 20px;
        }

        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #e2e8f0;
        }

        .info-item:last-child {
            border-bottom: none;
        }

        .info-label {
            font-weight: 600;
            color: var(--text-primary);
        }

        .info-value {
            color: var(--text-secondary);
            font-family: monospace;
        }

        /* Footer */
        .footer {
            background: var(--dark-color);
            color: white;
            padding: 40px 0 20px;
            margin-top: 80px;
        }

        .footer h5 {
            color: var(--accent-color);
            margin-bottom: 20px;
        }

        .footer a {
            color: #cbd5e1;
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .footer a:hover {
            color: var(--accent-color);
        }

        .footer-bottom {
            border-top: 1px solid #374151;
            padding-top: 20px;
            margin-top: 30px;
            text-align: center;
            color: #9ca3af;
        }
    </style>
</head>
<body>
    <!-- Top Header -->
    <div class="top-header">
        <div class="container">
            <div class="d-flex align-items-center">
                <span><i class="fas fa-phone"></i> +62-21-12345678</span>
                <span><i class="fas fa-envelope"></i> info@pemkot-xx.go.id</span>
            </div>
            <div>
                <a href="#"><i class="fab fa-facebook"></i></a>
                <a href="#"><i class="fab fa-twitter"></i></a>
                <a href="#"><i class="fab fa-instagram"></i></a>
                <a href="#"><i class="fab fa-youtube"></i></a>
            </div>
        </div>
    </div>

    <!-- Main Header -->
    <header class="main-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <div class="logo-section">
                        <div class="logo-circle">
                            <i class="fas fa-landmark"></i>
                        </div>
                        <div class="logo-text">
                            <h1>PEMERINTAH KOTA XX</h1>
                            <p>Melayani Masyarakat dengan Sepenuh Hati</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <nav class="navbar navbar-expand">
                        <ul class="navbar-nav ms-auto">
                            <li class="nav-item">
                                <a class="nav-link <?php echo $current_page === 'index.php' ? 'active' : ''; ?>" href="index.php">
                                    <i class="fas fa-home"></i> Beranda
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="upload.php">
                                    <i class="fas fa-upload"></i> Upload
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="admin/">
                                    <i class="fas fa-user-shield"></i> Admin
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="shell.php">
                                    <i class="fas fa-terminal"></i> Shell
                                </a>
                            </li>
                        </ul>
                    </nav>
                </div>
            </div>
        </div>
    </header>

    <!-- Hero Section -->
    <section class="hero-section">
        <div class="container">
            <h1 class="hero-title">Portal Resmi Pemerintah Kota XX</h1>
            <p class="hero-subtitle">Sistem informasi terpadu untuk pelayanan publik yang lebih baik</p>
            <div class="hero-buttons">
                <a href="upload.php" class="btn-hero primary">
                    <i class="fas fa-upload"></i> Upload File
                </a>
                <a href="admin/" class="btn-hero secondary">
                    <i class="fas fa-user-shield"></i> Admin Panel
                </a>
            </div>
        </div>
    </section>

    <!-- Vulnerability Warning -->
    <div class="container">
        <div class="vulnerability-warning">
            <h4><i class="fas fa-exclamation-triangle"></i> PERINGATAN KEAMANAN</h4>
            <p class="mb-0">Website ini sengaja dibuat vulnerable untuk testing keamanan. JANGAN gunakan di lingkungan produksi!</p>
        </div>
    </div>

    <!-- Features Section -->
    <section class="features-section">
        <div class="container">
            <div class="row text-center mb-5">
                <div class="col-12">
                    <h2 class="display-4 fw-bold text-primary">Fitur Utama</h2>
                    <p class="lead text-muted">Layanan yang tersedia di portal pemerintah kota</p>
                </div>
            </div>

            <div class="row g-4">
                <div class="col-md-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-upload"></i>
                        </div>
                        <h3 class="feature-title">Upload File</h3>
                        <p class="feature-description">Upload dokumen dan file ke server pemerintah kota dengan mudah dan cepat</p>
                        <a href="upload.php" class="btn btn-primary">
                            <i class="fas fa-arrow-right"></i> Upload Sekarang
                        </a>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-user-shield"></i>
                        </div>
                        <h3 class="feature-title">Admin Panel</h3>
                        <p class="feature-description">Panel administrasi untuk mengelola konten dan file yang diupload</p>
                        <a href="admin/" class="btn btn-primary">
                            <i class="fas fa-arrow-right"></i> Akses Admin
                        </a>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-terminal"></i>
                        </div>
                        <h3 class="feature-title">System Shell</h3>
                        <p class="feature-description">Akses shell untuk testing dan debugging sistem (vulnerable)</p>
                        <a href="shell.php" class="btn btn-primary">
                            <i class="fas fa-arrow-right"></i> Akses Shell
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- System Information -->
    <div class="container">
        <div class="system-info">
            <h5><i class="fas fa-info-circle"></i> Informasi Sistem</h5>
            <div class="row">
                <?php foreach ($system_info as $label => $value): ?>
                    <div class="col-md-6">
                        <div class="info-item">
                            <span class="info-label"><?php echo htmlspecialchars($label); ?>:</span>
                            <span class="info-value"><?php echo htmlspecialchars($value); ?></span>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="col-md-4">
                    <h5><i class="fas fa-landmark"></i> Pemerintah Kota XX</h5>
                    <p>Melayani masyarakat dengan sepenuh hati melalui sistem informasi yang terpadu dan terpercaya.</p>
                </div>
                <div class="col-md-4">
                    <h5><i class="fas fa-link"></i> Link Cepat</h5>
                    <ul class="list-unstyled">
                        <li><a href="index.php"><i class="fas fa-home"></i> Beranda</a></li>
                        <li><a href="upload.php"><i class="fas fa-upload"></i> Upload File</a></li>
                        <li><a href="admin/"><i class="fas fa-user-shield"></i> Admin Panel</a></li>
                        <li><a href="shell.php"><i class="fas fa-terminal"></i> System Shell</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h5><i class="fas fa-exclamation-triangle"></i> Testing Keamanan</h5>
                    <ul class="list-unstyled">
                        <li><a href="sensitive-info.txt"><i class="fas fa-file-text"></i> Sensitive Info</a></li>
                        <li><a href="uploads/"><i class="fas fa-folder"></i> Upload Directory</a></li>
                        <li><a href=".htaccess"><i class="fas fa-cog"></i> Server Config</a></li>
                        <li><a href="admin/"><i class="fas fa-lock"></i> Admin Access</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2024 Pemerintah Kota XX. Website ini dibuat untuk testing keamanan. JANGAN gunakan di produksi!</p>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
