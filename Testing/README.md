# SOC Incident Response Lifecycle (IRLC) - NIST 800-61r2 Framework

Sistem otomatis untuk menangani insiden defacement website berdasarkan framework IRLC NIST 800-61r2.

## 📋 Daftar Isi

- [Overview](#overview)
- [Arsitektur Sistem](#arsitektur-sistem)
- [Fase IRLC NIST 800-61r2](#fase-irlc-nist-800-61r2)
- [Instalasi](#instalasi)
- [Konfigurasi](#konfigurasi)
- [Penggunaan](#penggunaan)
- [Struktur File](#struktur-file)
- [Troubleshooting](#troubleshooting)
- [Kontribusi](#kontribusi)

## 🎯 Overview

Sistem ini dirancang untuk memberikan respons otomatis terhadap insiden defacement website dengan mengikuti framework Incident Response Lifecycle (IRLC) dari NIST 800-61r2. Sistem terintegrasi dengan Wazuh SIEM dan dapat menangani seluruh siklus insiden dari deteksi hingga pemulihan.

### Fitur Utama

- ✅ **Deteksi Otomatis**: Integrasi dengan Wazuh untuk deteksi real-time
- ✅ **Containment Otomatis**: Isolasi ancaman secara otomatis
- ✅ **Eradication**: Penghapusan ancaman dengan multiple scanning
- ✅ **Recovery**: Pemulihan sistem dari backup
- ✅ **Threat Intelligence**: Integrasi dengan MISP
- ✅ **Logging & Reporting**: Dokumentasi lengkap setiap insiden
- ✅ **Konfigurasi Terpusat**: Manajemen konfigurasi yang mudah

## 🏗️ Arsitektur Sistem

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Wazuh SIEM    │───▶│  SOC IRLC      │───▶│   MISP Server   │
│   (Detection)   │    │  (Processing)   │    │  (Threat Intel) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Web Server     │◀───│  Backup System  │    │  Quarantine     │
│  (Target)       │    │  (Recovery)     │    │  (Isolation)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔄 Fase IRLC NIST 800-61r2

### 1. Preparation Phase
- Validasi konfigurasi sistem
- Persiapan direktori dan file yang diperlukan
- Verifikasi integrasi dengan komponen eksternal

### 2. Detection & Analysis Phase
- Deteksi insiden melalui Wazuh alerts
- Analisis IoC (Indicators of Compromise)
- Klasifikasi tingkat keparahan insiden

### 3. Containment Phase
- Isolasi IP penyerang menggunakan iptables
- Aktivasi mode maintenance website
- Pembatasan akses ke sistem yang terinfeksi

### 4. Eradication Phase
- Scanning file mencurigakan dengan ClamAV
- Deteksi pattern berbahaya dengan YARA
- Karantina file yang terinfeksi

### 5. Recovery Phase
- Restore website dari backup Git
- Restore file dinamis dari backup remote
- Verifikasi integritas sistem

### 6. Post-Incident Activity Phase
- Dokumentasi lengkap insiden
- Pengiriman threat intelligence ke MISP
- Analisis lessons learned

## 🚀 Instalasi

### Prerequisites

- Python 3.7+
- Wazuh SIEM
- Git repository untuk backup
- MISP server (opsional)
- ClamAV antivirus
- YARA rules

### Langkah Instalasi

1. **Clone Repository**
```bash
git clone <repository-url>
cd soc-incident-response
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Setup Konfigurasi**
```bash
sudo cp config.conf /etc/soc-config/
sudo chmod 600 /etc/soc-config/config.conf
```

4. **Setup Direktori**
```bash
sudo mkdir -p /var/soc-backup /var/soc-quarantine /var/log/soc-incident-response
sudo chown -R www-data:www-data /var/soc-backup /var/soc-quarantine
```

5. **Integrasi Wazuh**
```bash
# Copy script ke direktori Wazuh active response
sudo cp soc_incident_response.py /var/ossec/active-response/bin/
sudo chmod 755 /var/ossec/active-response/bin/soc_incident_response.py
```

## ⚙️ Konfigurasi

### File Konfigurasi Utama

File `config.conf` berisi semua konfigurasi sistem:

```ini
# Direktori web yang akan diproteksi
WEB_DIR="/var/www/html"

# Direktori backup utama
BACKUP_DIR="/var/soc-backup"

# Direktori karantina
QUARANTINE_DIR="/var/soc-quarantine"

# Rule IDs untuk deteksi
DEFACE_RULE_IDS="550,554,5501,5502,5503,5504,100001,100002"
ATTACK_RULE_IDS="5710,5712,5715,5760,100003,100004"
```

### Konfigurasi Wazuh

Tambahkan ke file `/var/ossec/etc/ossec.conf`:

```xml
<active-response>
  <command>soc_incident_response</command>
  <location>local</location>
  <level>10</level>
</active-response>
```

## 📖 Penggunaan

### Mode Otomatis (Wazuh Integration)

Sistem akan berjalan otomatis ketika Wazuh mendeteksi alert yang sesuai dengan rule ID yang dikonfigurasi.

### Mode Manual

1. **Test Sistem**
```bash
python3 soc_incident_response.py test
```

2. **Cek Status**
```bash
python3 soc_incident_response.py status
```

3. **Manual Containment**
```bash
python3 containment.py enable-maintenance
python3 containment.py block-ip 192.168.1.100
```

4. **Manual Eradication**
```bash
python3 eradicationV2.py scan-directory /var/www/html
```

5. **Manual Recovery**
```bash
python3 restore.py --auto
```

## 📁 Struktur File

```
soc-incident-response/
├── config.conf                 # Konfigurasi terpusat
├── soc_incident_response.py    # Script integrasi utama
├── Deteksi-IoC.py             # Fase Detection & Analysis
├── containment.py             # Fase Containment
├── eradicationV2.py           # Fase Eradication
├── restore.py                 # Fase Recovery (interaktif)
├── restore_auto.py            # Fase Recovery (otomatis)
├── MISPconvert.py             # Fase Post-Incident
├── requirements.txt           # Dependencies Python
├── README.md                  # Dokumentasi
└── scripts/                   # Script pendukung
    ├── monitoring_setup.sh
    ├── installV2.sh
    ├── MISP-setup.sh
    ├── wazuhinstall.sh
    └── backup.sh
```

## 🔧 Troubleshooting

### Masalah Umum

1. **Script tidak ditemukan**
```bash
# Pastikan path script benar
ls -la /var/ossec/active-response/bin/soc_incident_response.py
```

2. **Permission denied**
```bash
# Set permission yang benar
sudo chmod 755 /var/ossec/active-response/bin/soc_incident_response.py
```

3. **Konfigurasi tidak terbaca**
```bash
# Cek file konfigurasi
sudo cat /etc/soc-config/config.conf
```

4. **Log tidak muncul**
```bash
# Cek direktori log
sudo ls -la /var/log/soc-incident-response/
```

### Debug Mode

Aktifkan debug mode di `config.conf`:
```ini
DEBUG_MODE="true"
LOG_LEVEL="DEBUG"
```

### Log Files

- **Main Log**: `/var/log/soc-incident-response/soc_incident_response.log`
- **Containment Log**: `/var/log/wazuh/active-response/containment.log`
- **Eradication Log**: `/var/log/wazuh/active-response/eradication.log`
- **Restore Log**: `/var/log/wazuh/active-response/restore.log`

## 📊 Monitoring

### Metrics yang Dimonitor

- Jumlah insiden per hari/minggu/bulan
- Waktu respons rata-rata
- Tingkat keberhasilan setiap fase
- File yang dikarantina
- IP yang diblokir

### Dashboard

Sistem menyediakan laporan dalam format JSON yang dapat diintegrasikan dengan dashboard monitoring.

## 🔒 Keamanan

### Best Practices

1. **File Permissions**
   - Konfigurasi: 600
   - Script: 755
   - Log: 644

2. **Network Security**
   - Gunakan SSH key untuk remote backup
   - Enkripsi komunikasi dengan MISP
   - Batasi akses ke direktori backup

3. **Audit Trail**
   - Semua aktivitas dicatat
   - Laporan insiden otomatis
   - Backup log terpusat

## 🤝 Kontribusi

1. Fork repository
2. Buat feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buat Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 📞 Support

Untuk dukungan teknis atau pertanyaan:
- Email: support@example.com
- Documentation: [Wiki](https://github.com/example/soc-incident-response/wiki)
- Issues: [GitHub Issues](https://github.com/example/soc-incident-response/issues)

---

**Note**: Sistem ini dirancang untuk lingkungan production. Pastikan untuk melakukan testing yang menyeluruh sebelum deployment. 