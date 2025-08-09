# VULNERABLE WEB SYSTEM - INTEGRATED SOLUTION

## Deskripsi
Sistem web vulnerable yang terintegrasi untuk testing keamanan, termasuk WordPress dengan Contact Form 7 dan website pemerintahan.

## Fitur
- **WordPress Vulnerable Site** (Port 8000)
  - Plugin Contact Form 7 dengan arbitrary file upload
  - File execution via .htaccess
  - Weak authentication

- **Government Website** (Port 8080)
  - Admin panel dengan weak authentication
  - File upload tanpa validasi
  - PHP shell access
  - Directory listing

## Instalasi

### 1. Clone Repository
```bash
git clone <repository-url>
cd web-vuln
```

### 2. Jalankan Installer
```bash
sudo bash install.sh
```

### 3. Testing
```bash
sudo bash test.sh
```

### 4. Cleanup (Setelah Testing)
```bash
sudo bash cleanup.sh
```

## Struktur Direktori
```
web-vuln/
├── main.sh                    # Script utama terintegrasi
├── install.sh                 # Script instalasi
├── cleanup.sh                 # Script cleanup
├── test.sh                    # Script testing
├── config/                    # Direktori konfigurasi
│   └── setup.sh              # Script konfigurasi
├── templates/                 # Template HTML
│   ├── government_website_enhanced.html
│   └── admin_panel_enhanced.html
├── php/                       # File PHP
│   ├── index.php
│   ├── upload.php
│   ├── shell.php
│   ├── .htaccess
│   ├── sensitive-info.txt
│   └── admin/
│       ├── admin_login.php
│       └── admin_panel.php
├── docs/                      # Dokumentasi
│   ├── README.md
│   ├── README_MASTER.md
│   └── INSTALLATION.md
├── .gitignore                 # Git ignore file
└── LICENSE                    # License file
```

Dengan struktur ini, Anda memiliki:

1. **Satu script utama** (`main.sh`) yang mengintegrasikan semua fungsi
2. **Script terpisah** untuk setiap fungsi utama (install, test, cleanup, config)
3. **Struktur direktori yang terorganisir** dan tidak membingungkan
4. **Tidak ada fungsi yang tumpang tindih** - setiap script memiliki fungsi spesifik
5. **Sistem yang mudah di-maintain** dan di-deploy ke Git
6. **Dokumentasi yang lengkap** dan terstruktur

Untuk menggunakan sistem ini:

1. **Clone repository** ke server
2. **Jalankan `main.sh`** untuk menu interaktif
3. **Pilih opsi** sesuai kebutuhan (install, test, configure, cleanup)
4. **Upload ke Git** dengan struktur yang sudah terorganisir

Apakah ada bagian yang perlu saya jelaskan lebih detail atau ada penyesuaian yang diinginkan?
