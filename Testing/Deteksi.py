#!/usr/bin/env python3
import json
import datetime
import os
import sys
import logging
from logging.handlers import RotatingFileHandler

# --- Konfigurasi Terpusat ---
CONFIG_FILES = ["/etc/soc-config/config.conf", "/etc/web-backup/config.conf"]

def load_config():
    """Memuat konfigurasi dari file terpusat."""
    config = {}
    config_file = None
    
    # Cari config file yang ada
    for cf in CONFIG_FILES:
        if os.path.exists(cf):
            config_file = cf
            break
    
    if not config_file:
        print(f"Error: File konfigurasi tidak ditemukan di: {', '.join(CONFIG_FILES)}")
        return config

    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and '=' in line and not line.startswith('#'):
                    line_content = line.split('#', 1)[0].strip()
                    if not line_content:
                        continue
                    key, value = line_content.split('=', 1)
                    config[key.strip()] = value.strip().strip('"\'')
        print(f"Konfigurasi dimuat dari: {config_file}")
    except Exception as e:
        print(f"Error membaca file konfigurasi {config_file}: {e}")
    return config

# Load konfigurasi
config = load_config()

# --- Konfigurasi dari file terpusat ---
ALERTS_FILE = config.get('WAZUH_ALERTS_FILE', '/var/ossec/logs/alerts/alerts.json')
OUTPUT_FILE = config.get('DETECTION_OUTPUT_FILE', '/tmp/active_response_500550.log')
LOG_FILE = config.get('DETECTION_LOG_FILE', '/tmp/find_last_500550_debug.log')
IOC_DATA_FILE = config.get('IOC_DATA_FILE', '/tmp/detected_ioc_data.json')

# Rule IDs untuk deteksi dari konfigurasi
DEFACE_RULE_IDS = config.get('DEFACE_RULE_IDS', '550,554,5501,5502,5503,5504,100001,100002').split(',')
ATTACK_RULE_IDS = config.get('ATTACK_RULE_IDS', '5710,5712,5715,5760,100003,100004').split(',')

def setup_logging():
    """Setup logging yang konsisten dengan modul lain"""
    logger = logging.getLogger('soc_detection')
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        # File handler
        log_file = "/var/log/soc-incident-response/detection.log"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger

def log_debug(msg):
    """Fungsi untuk menulis log debug."""
    try:
        # Pastikan direktori log ada
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        with open(LOG_FILE, 'a') as f:
            f.write(f"{datetime.datetime.now()} - {msg}\n")
    except Exception as e:
        print(f"Error menulis log: {e}")

def extract_ioc_data(alert):
    """Mengekstrak data IoC dari alert Wazuh."""
    ioc_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'alert_id': alert.get('id'),
        'rule_id': alert.get('rule', {}).get('id'),
        'rule_description': alert.get('rule', {}).get('description'),
        'level': alert.get('rule', {}).get('level'),
        'source_ip': None,
        'target_file': None,
        'ioc_type': None,
        'ioc_value': None,
        'full_alert': alert
    }
    
    # Ekstrak source IP dari alert
    if 'data' in alert:
        for data_item in alert['data']:
            if 'srcip' in data_item:
                ioc_data['source_ip'] = data_item['srcip']
            if 'file' in data_item:
                ioc_data['target_file'] = data_item['file']
    
    # Tentukan tipe IoC berdasarkan rule ID
    rule_id = str(ioc_data['rule_id'])
    if rule_id in DEFACE_RULE_IDS:
        ioc_data['ioc_type'] = 'defacement'
    elif rule_id in ATTACK_RULE_IDS:
        ioc_data['ioc_type'] = 'attack'
    else:
        ioc_data['ioc_type'] = 'unknown'
    
    # Ekstrak nilai IoC dari alert
    if 'data' in alert:
        for data_item in alert['data']:
            if 'url' in data_item:
                ioc_data['ioc_value'] = data_item['url']
            elif 'file' in data_item:
                ioc_data['ioc_value'] = data_item['file']
            elif 'srcip' in data_item:
                ioc_data['ioc_value'] = data_item['srcip']
    
    return ioc_data

def save_ioc_data(ioc_data_list):
    """Menyimpan data IoC ke file JSON untuk digunakan fase berikutnya."""
    try:
        # Pastikan direktori output ada
        output_dir = os.path.dirname(IOC_DATA_FILE)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        with open(IOC_DATA_FILE, 'w') as f:
            json.dump({
                'detection_timestamp': datetime.datetime.now().isoformat(),
                'total_iocs': len(ioc_data_list),
                'ioc_data': ioc_data_list
            }, f, indent=2)
        log_debug(f"Data IoC berhasil disimpan ke {IOC_DATA_FILE}")
        return True
    except Exception as e:
        log_debug(f"Error menyimpan data IoC: {str(e)}")
        return False

def main():
    log_debug(f"Skrip Deteksi-IoC.py dimulai.")

    # Cek apakah ada input dari stdin (untuk integrasi dengan Wazuh)
    alert_data = None
    if not sys.stdin.isatty():
        try:
            alert_data = sys.stdin.read().strip()
            log_debug(f"Menerima alert data dari stdin: {len(alert_data)} karakter")
        except Exception as e:
            log_debug(f"Error membaca dari stdin: {str(e)}")

    # Jika ada input dari stdin, gunakan itu
    if alert_data:
        try:
            alert = json.loads(alert_data)
            ioc_data = extract_ioc_data(alert)
            
            # Simpan data IoC
            save_ioc_data([ioc_data])
            
            # Tulis ke output file
            with open(OUTPUT_FILE, 'w') as out:
                out.write("==== INCIDENT REPORT (IoC Detection) ====\n")
                out.write(json.dumps(ioc_data, indent=4))
                out.write("\n==== END OF REPORT ====\n")
            
            log_debug(f"Berhasil memproses alert dari stdin - Rule ID: {ioc_data['rule_id']}")
            return
            
        except json.JSONDecodeError as e:
            log_debug(f"Error parsing JSON dari stdin: {str(e)}")
        except Exception as e:
            log_debug(f"Error memproses alert dari stdin: {str(e)}")

    # Cek apakah file alerts.json ada
    if not os.path.isfile(ALERTS_FILE):
        log_debug(f"Error: File {ALERTS_FILE} tidak ditemukan!")
        return

    # Membaca semua baris dari file alerts.json
    try:
        with open(ALERTS_FILE, 'r') as f:
            lines = f.readlines()
        log_debug(f"Berhasil membaca {len(lines)} baris dari {ALERTS_FILE}.")
    except Exception as e:
        log_debug(f"Error: Gagal membaca file alerts: {str(e)}")
        return

    detected_iocs = []
    latest_alert = None
    
    # Mencari dari baris terakhir ke atas untuk efisiensi
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
            rule_id = str(alert.get('rule', {}).get('id', ''))
            
            # Cek apakah rule ID cocok dengan target
            if rule_id in DEFACE_RULE_IDS or rule_id in ATTACK_RULE_IDS:
                ioc_data = extract_ioc_data(alert)
                detected_iocs.append(ioc_data)
                
                if latest_alert is None:
                    latest_alert = alert
                
                log_debug(f"Menemukan IoC - Rule ID: {rule_id}, Tipe: {ioc_data['ioc_type']}")
                
        except Exception:
            # Mengabaikan baris yang bukan format JSON yang valid
            continue

    # Simpan semua data IoC yang terdeteksi
    if detected_iocs:
        save_ioc_data(detected_iocs)
        log_debug(f"Total {len(detected_iocs)} IoC terdeteksi")

    # Jika alert yang cocok ditemukan, tulis ke file output
    if latest_alert:
        try:
            with open(OUTPUT_FILE, 'w') as out:
                out.write("==== INCIDENT REPORT (Last Alert Found) ====\n")
                # Menggunakan json.dumps untuk format yang lebih rapi
                out.write(json.dumps(latest_alert, indent=4))
                out.write("\n==== END OF REPORT ====\n")
            log_debug(f"Berhasil menulis laporan ke {OUTPUT_FILE}")
        except Exception as e:
            log_debug(f"Error: Gagal menulis file output: {str(e)}")
    else:
        # Pesan log jika tidak ada alert yang cocok ditemukan
        log_debug(f"Tidak menemukan alert dengan rule_id target di seluruh file.")

if __name__ == "__main__":
    main()
