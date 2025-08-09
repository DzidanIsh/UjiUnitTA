<?php
session_start();

// Check if user is logged in
if (!isset($_SESSION['admin']) || $_SESSION['admin'] !== true) {
    header('Location: admin_login.php');
    exit();
}

$username = $_SESSION['username'] ?? 'Admin';
$upload_dir = '../uploads/';
$message = '';
$message_type = '';

// Ensure upload directory exists
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

// Process file upload
if ($_POST && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    
    if ($file['error'] === UPLOAD_ERR_OK) {
        $filename = $file['name'];
        $destination = $upload_dir . $filename;
        
        // VULNERABLE: No file type validation
        // VULNERABLE: No file size limit
        // VULNERABLE: No file content validation
        
        if (move_uploaded_file($file['tmp_name'], $destination)) {
            $message = "File berhasil diupload: " . htmlspecialchars($filename);
            $message_type = 'success';
        } else {
            $message = "Gagal mengupload file: " . htmlspecialchars($filename);
            $message_type = 'danger';
        }
    } else {
        $message = "Error dalam upload file: " . $file['error'];
        $message_type = 'danger';
    }
}

// Get list of uploaded files
$uploaded_files = [];
if (is_dir($upload_dir)) {
    $files = scandir($upload_dir);
    foreach ($files as $file) {
        if ($file !== '.' && $file !== '..') {
            $file_path = $upload_dir . $file;
            $uploaded_files[] = [
                'name' => $file,
                'size' => filesize($file_path),
                'date' => filemtime($file_path),
                'type' => mime_content_type($file_path)
            ];
        }
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: admin_login.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Pemerintah Kota XX</title>
    
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
            background-color: var(--light-color);
            color: var(--text-primary);
        }

        .navbar {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }

        .sidebar {
            background: white;
            min-height: calc(100vh - 76px);
            box-shadow: 2px 0 10px rgba(0,0,0,0.1);
            padding: 20px 0;
        }

        .sidebar .nav-link {
            color: var(--text-secondary);
            padding: 12px 20px;
            border-radius: 0;
            transition: all 0.3s ease;
        }

        .sidebar .nav-link:hover,
        .sidebar .nav-link.active {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
        }

        .main-content {
            padding: 30px;
        }

        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            margin-bottom: 30px;
        }

        .card-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border-radius: 15px 15px 0 0 !important;
            border: none;
            padding: 20px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            border: none;
            border-radius: 10px;
            padding: 12px 25px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        }

        .form-control {
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            padding: 12px 15px;
            transition: all 0.3s ease;
        }

        .form-control:focus {
            border-color: var(--secondary-color);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        .table {
            border-radius: 10px;
            overflow: hidden;
        }

        .table thead th {
            background: var(--light-color);
            border: none;
            font-weight: 600;
            color: var(--primary-color);
        }

        .vulnerability-warning {
            background: linear-gradient(135deg, var(--warning-color), #f97316);
            color: white;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }

        .file-upload-area {
            border: 2px dashed var(--secondary-color);
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            background: #f8fafc;
            transition: all 0.3s ease;
        }

        .file-upload-area:hover {
            background: #e2e8f0;
            border-color: var(--primary-color);
        }

        .stats-card {
            background: linear-gradient(135deg, var(--success-color), #059669);
            color: white;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            margin-bottom: 20px;
        }

        .stats-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="fas fa-shield-alt"></i> Admin Panel
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    <i class="fas fa-user"></i> <?php echo htmlspecialchars($username); ?>
                </span>
                <a class="nav-link" href="?logout=1">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 sidebar">
                <ul class="nav flex-column">
                    <li class="nav-item">
                        <a class="nav-link active" href="#">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#upload-section">
                            <i class="fas fa-upload"></i> Upload File
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#files-section">
                            <i class="fas fa-folder"></i> File Manager
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#vulnerabilities">
                            <i class="fas fa-exclamation-triangle"></i> Vulnerabilities
                        </a>
                    </li>
                </ul>
            </div>

            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 main-content">
                <!-- Vulnerability Warning -->
                <div class="vulnerability-warning">
                    <h5><i class="fas fa-exclamation-triangle"></i> PERINGATAN KEAMANAN</h5>
                    <p class="mb-0">Sistem ini sengaja dibuat vulnerable untuk testing keamanan. JANGAN gunakan di lingkungan produksi!</p>
                </div>

                <!-- Stats Cards -->
                <div class="row">
                    <div class="col-md-4">
                        <div class="stats-card">
                            <div class="stats-number"><?php echo count($uploaded_files); ?></div>
                            <div>Total Files</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stats-card" style="background: linear-gradient(135deg, var(--warning-color), #f97316);">
                            <div class="stats-number">5+</div>
                            <div>Vulnerabilities</div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stats-card" style="background: linear-gradient(135deg, var(--danger-color), #dc2626);">
                            <div class="stats-number">High</div>
                            <div>Risk Level</div>
                        </div>
                    </div>
                </div>

                <!-- File Upload Section -->
                <div class="card" id="upload-section">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-upload"></i> Upload File
                        </h5>
                    </div>
                    <div class="card-body">
                        <?php if ($message): ?>
                            <div class="alert alert-<?php echo $message_type; ?> alert-dismissible fade show">
                                <i class="fas fa-info-circle"></i>
                                <?php echo $message; ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        <?php endif; ?>

                        <div class="file-upload-area">
                            <form method="POST" enctype="multipart/form-data">
                                <i class="fas fa-cloud-upload-alt fa-3x text-primary mb-3"></i>
                                <h5>Upload File Baru</h5>
                                <p class="text-muted">Pilih file yang ingin diupload ke server</p>
                                
                                <div class="mb-3">
                                    <input type="file" 
                                           class="form-control" 
                                           name="file" 
                                           required>
                                </div>
                                
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-upload"></i> Upload File
                                </button>
                            </form>
                        </div>

                        <div class="mt-4">
                            <h6><i class="fas fa-info-circle"></i> Informasi Upload:</h6>
                            <ul class="text-muted">
                                <li>File akan disimpan di direktori: <code><?php echo htmlspecialchars($upload_dir); ?></code></li>
                                <li>Tidak ada validasi tipe file (VULNERABLE)</li>
                                <li>Tidak ada batasan ukuran file (VULNERABLE)</li>
                                <li>File dapat dieksekusi langsung (VULNERABLE)</li>
                            </ul>
                        </div>
                    </div>
                </div>

                <!-- Files List Section -->
                <div class="card" id="files-section">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-folder"></i> File Manager
                        </h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($uploaded_files)): ?>
                            <div class="text-center text-muted py-4">
                                <i class="fas fa-folder-open fa-3x mb-3"></i>
                                <h5>Belum ada file yang diupload</h5>
                                <p>Upload file pertama Anda menggunakan form di atas</p>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Nama File</th>
                                            <th>Ukuran</th>
                                            <th>Tipe</th>
                                            <th>Tanggal Upload</th>
                                            <th>Aksi</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($uploaded_files as $file): ?>
                                            <tr>
                                                <td>
                                                    <i class="fas fa-file"></i>
                                                    <?php echo htmlspecialchars($file['name']); ?>
                                                </td>
                                                <td><?php echo number_format($file['size'] / 1024, 2); ?> KB</td>
                                                <td>
                                                    <span class="badge bg-secondary">
                                                        <?php echo htmlspecialchars($file['type']); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo date('d/m/Y H:i', $file['date']); ?></td>
                                                <td>
                                                    <a href="../uploads/<?php echo urlencode($file['name']); ?>" 
                                                       class="btn btn-sm btn-outline-primary"
                                                       target="_blank">
                                                        <i class="fas fa-eye"></i> View
                                                    </a>
                                                    <a href="../uploads/<?php echo urlencode($file['name']); ?>" 
                                                       class="btn btn-sm btn-outline-success"
                                                       download>
                                                        <i class="fas fa-download"></i> Download
                                                    </a>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Vulnerabilities Section -->
                <div class="card" id="vulnerabilities">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-exclamation-triangle"></i> Daftar Kerentanan
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="alert alert-danger">
                                    <h6><i class="fas fa-times-circle"></i> Unrestricted File Upload</h6>
                                    <p class="mb-0">Tidak ada validasi tipe file, ukuran, atau konten</p>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="alert alert-danger">
                                    <h6><i class="fas fa-times-circle"></i> File Execution</h6>
                                    <p class="mb-0">File yang diupload dapat dieksekusi langsung</p>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="alert alert-warning">
                                    <h6><i class="fas fa-exclamation-triangle"></i> Weak Authentication</h6>
                                    <p class="mb-0">Kredensial login yang lemah dan mudah ditebak</p>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="alert alert-warning">
                                    <h6><i class="fas fa-exclamation-triangle"></i> Directory Listing</h6>
                                    <p class="mb-0">Struktur direktori dapat dilihat publik</p>
                                </div>
                            </div>
                        </div>

                        <div class="mt-3">
                            <h6><i class="fas fa-code"></i> Contoh Exploit:</h6>
                            <div class="bg-dark text-light p-3 rounded">
                                <code>
                                    # Upload PHP shell<br>
                                    curl -X POST -F "file=@shell.php" http://localhost:8080/admin/upload.php<br><br>
                                    
                                    # Execute commands<br>
                                    curl "http://localhost:8080/uploads/shell.php?cmd=whoami"<br>
                                    curl "http://localhost:8080/uploads/shell.php?cmd=ls -la"
                                </code>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
