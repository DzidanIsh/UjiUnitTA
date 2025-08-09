#!/usr/bin/env python3

"""
SOC MISP Integration Script - NIST 800-61 Incident Response Framework
Post-Incident Activity Phase: Mengirim threat intelligence ke MISP platform
"""

import os
import sys
import json
import logging
from datetime import datetime

# Import MISP library yang diperlukan
try:
    from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
    MISP_AVAILABLE = True
except ImportError:
    MISP_AVAILABLE = False
    print("Warning: Library pymisp tidak tersedia. MISP integration akan dinonaktifkan.")

# --- Konfigurasi Terpusat ---
CONFIG_FILES = ["/etc/soc-config/config.conf", "/etc/web-backup/config.conf"]

def load_config():
    """Load konfigurasi dengan validasi yang lebih baik"""
    config_file = "/etc/soc-config/config.conf"
    
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"File konfigurasi tidak ditemukan: {config_file}")
    
    config = {}
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip().strip('"')
    except Exception as e:
        raise RuntimeError(f"Gagal membaca konfigurasi: {str(e)}")
    
    # Validasi variabel yang diperlukan
    required_vars = ['MISP_URL', 'MISP_KEY', 'INCIDENT_REPORTS_DIR']
    missing_vars = [var for var in required_vars if var not in config]
    
    if missing_vars:
        raise ValueError(f"Variabel konfigurasi yang diperlukan tidak ditemukan: {missing_vars}")
    
    return config

# Load konfigurasi
config = load_config()

# --- Konfigurasi MISP dari file terpusat ---
misp_url = config.get('MISP_URL', 'https://192.168.28.135')
misp_key = config.get('MISP_KEY', 'XweOnEWOtWFmIbW585H2m03R3SIZRmIKxrza73WB')
misp_verifycert = config.get('MISP_VERIFY_CERT', 'false').lower() == 'true'

# Setup logging
LOG_FILE = config.get('MISP_LOG_FILE', '/var/log/soc-incident-response/misp.log')
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}", file=sys.stderr)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('soc_misp')

def process_incident_data(input_data_str):
    """Memproses data insiden dan mengirim ke MISP."""
    if not MISP_AVAILABLE:
        error_msg = "Library pymisp tidak tersedia. MISP integration dinonaktifkan."
        logger.error(error_msg)
        print(f"ERROR: {error_msg}")
        return False, error_msg
    
    try:
        # Parse input data (bisa berupa alert langsung atau data lengkap dengan IoC)
        input_data = json.loads(input_data_str)
        
        # Cek apakah ini data lengkap dengan IoC atau alert langsung
        if isinstance(input_data, dict) and 'alert' in input_data and 'ioc_data' in input_data:
            # Data lengkap dengan IoC
            alert = input_data['alert']
            ioc_data = input_data['ioc_data']
            logger.info("Memproses data lengkap dengan IoC untuk MISP")
        else:
            # Alert langsung (backward compatibility)
            alert = input_data
            ioc_data = None
            logger.info("Memproses alert langsung untuk MISP")
        
        # Koneksi ke MISP
        misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
        
        # Buat Event Baru
        event = MISPEvent()
        event.info = f"SOC Incident Response - {alert.get('rule', {}).get('description', 'Unknown Threat')}"
        event.distribution = 0  # Your organization only
        event.threat_level_id = 2  # Medium threat
        event.analysis = 2  # Completed analysis
        
        # Tambahkan tag berdasarkan tipe insiden
        rule_id = str(alert.get('rule', {}).get('id', ''))
        deface_rule_ids = config.get('DEFACE_RULE_IDS', '').split(',')
        attack_rule_ids = config.get('ATTACK_RULE_IDS', '').split(',')
        
        if rule_id in deface_rule_ids:
            event.add_tag('defacement')
        elif rule_id in attack_rule_ids:
            event.add_tag('attack')
        
        response = misp.add_event(event)
        event_id = response['Event']['id']
        logger.info(f'Event MISP berhasil dibuat dengan ID: {event_id}')
        print(f'Event MISP berhasil dibuat dengan ID: {event_id}')
        
        # Tambahkan atribut dari alert
        alert_attributes = []
        
        # Rule ID
        if rule_id:
            alert_attributes.append({
                'type': 'text',
                'value': f"Rule ID: {rule_id}",
                'category': 'Other',
                'comment': 'Wazuh Rule ID'
            })
        
        # Source IP dari alert
        if 'data' in alert:
            for data_item in alert['data']:
                if 'srcip' in data_item:
                    alert_attributes.append({
                        'type': 'ip-src',
                        'value': data_item['srcip'],
                        'category': 'Network activity',
                        'comment': 'Source IP from alert'
                    })
                if 'file' in data_item:
                    alert_attributes.append({
                        'type': 'filename',
                        'value': data_item['file'],
                        'category': 'Payload delivery',
                        'comment': 'Target file from alert'
                    })
        
        # Tambahkan atribut dari IoC data
        if ioc_data and 'ioc_data' in ioc_data:
            for ioc in ioc_data['ioc_data']:
                # Source IP dari IoC
                if ioc.get('source_ip'):
                    alert_attributes.append({
                        'type': 'ip-src',
                        'value': ioc['source_ip'],
                        'category': 'Network activity',
                        'comment': f"Source IP from IoC - {ioc.get('ioc_type', 'unknown')}"
                    })
                
                # Target file dari IoC
                if ioc.get('target_file'):
                    alert_attributes.append({
                        'type': 'filename',
                        'value': ioc['target_file'],
                        'category': 'Payload delivery',
                        'comment': f"Target file from IoC - {ioc.get('ioc_type', 'unknown')}"
                    })
                
                # IOC value
                if ioc.get('ioc_value'):
                    # Tentukan tipe berdasarkan nilai
                    ioc_value = ioc['ioc_value']
                    if ioc_value.startswith('http'):
                        attr_type = 'url'
                    elif '.' in ioc_value and len(ioc_value.split('.')) == 4:
                        attr_type = 'ip-src'
                    else:
                        attr_type = 'text'
                    
                    alert_attributes.append({
                        'type': attr_type,
                        'value': ioc_value,
                        'category': 'Payload delivery',
                        'comment': f"IoC value - {ioc.get('ioc_type', 'unknown')}"
                    })
        
        # Tambahkan semua atribut ke MISP
        for attr_data in alert_attributes:
            attr = MISPAttribute()
            attr.type = attr_data['type']
            attr.value = attr_data['value']
            attr.category = attr_data['category']
            attr.comment = attr_data['comment']
            attr.to_ids = True if attr_data['type'] in ['sha256', 'ip-src', 'url', 'md5'] else False
            
            resp = misp.add_attribute(event_id, attr)
            if 'Attribute' in resp:
                logger.info(f'Attribute {attr_data["type"]} ({attr_data["value"]}) berhasil ditambahkan!')
                print(f'Attribute {attr_data["type"]} ({attr_data["value"]}) berhasil ditambahkan!')
            else:
                logger.error(f'Gagal menambahkan attribute {attr_data["type"]}: {resp}')
                print(f'Gagal menambahkan attribute {attr_data["type"]}: {resp}')
        
        logger.info(f"Total {len(alert_attributes)} atribut berhasil ditambahkan ke MISP event {event_id}")
        print(f"Total {len(alert_attributes)} atribut berhasil ditambahkan ke MISP event {event_id}")
        
        return True, f"MISP event {event_id} berhasil dibuat dengan {len(alert_attributes)} atribut"
        
    except Exception as e:
        error_msg = f"Error memproses data untuk MISP: {e}"
        logger.error(error_msg)
        print(f"ERROR: {error_msg}")
        return False, error_msg

def main():
    """Main function untuk MISP integration."""
    try:
        # Check if running with input from stdin (Wazuh integration)
        if not sys.stdin.isatty():
            try:
                input_data = sys.stdin.read().strip()
                logger.info("Menerima data dari stdin untuk MISP")
                success, details = process_incident_data(input_data)
                if success:
                    logger.info(f"MISP integration berhasil: {details}")
                    print(f"SUCCESS: {details}")
                else:
                    logger.error(f"MISP integration gagal: {details}")
                    print(f"ERROR: {details}")
            except Exception as e:
                logger.error(f"Error membaca dari stdin: {e}")
                print(f"ERROR: {e}")
        else:
            # Manual mode - gunakan sample data
            logger.info("Menjalankan MISP integration dalam mode manual")
            sample_data = {
                'alert': {
                    'rule': {
                        'id': '550',
                        'description': 'Sample Defacement Alert'
                    },
                    'data': [
                        {'srcip': '192.168.1.77'},
                        {'file': '/var/www/html/webshell.php'}
                    ]
                },
                'ioc_data': {
                    'ioc_data': [
                        {
                            'source_ip': '192.168.1.77',
                            'target_file': '/var/www/html/webshell.php',
                            'ioc_value': 'http://example.com/hack.php',
                            'ioc_type': 'defacement'
                        }
                    ]
                }
            }
            
            success, details = process_incident_data(json.dumps(sample_data))
            if success:
                logger.info(f"MISP integration berhasil: {details}")
                print(f"SUCCESS: {details}")
            else:
                logger.error(f"MISP integration gagal: {details}")
                print(f"ERROR: {details}")
    
    except Exception as e:
        logger.error(f"Error dalam main MISP: {e}")
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()

