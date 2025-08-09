#!/usr/bin/env python3

"""
SOC Eradication Script - NIST 800-61 Incident Response Framework
Eradication Phase: Menghilangkan ancaman dari sistem dan mencegah penyebaran
"""

import os
import sys
import json
import logging
import shutil
import hashlib
import re
import requests
from datetime import datetime
from pathlib import Path
import math

# --- IOC PATCH START - Better error handling ---
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False
    logging.warning("Library 'pefile' tidak terinstal. PE file analysis dinonaktifkan.")

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    lief = None
    LIEF_AVAILABLE = False
    logging.warning("Library 'lief' tidak terinstal. Binary analysis dinonaktifkan.")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    magic = None
    MAGIC_AVAILABLE = False
    logging.warning("Library 'python-magic' tidak terinstal. Deteksi tipe MIME mungkin kurang akurat.")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False
    logging.warning("Library 'yara-python' tidak terinstal. Scan YARA akan dinonaktifkan.")

try:
    import pyclamd
    CLAMAV_AVAILABLE = True
except ImportError:
    pyclamd = None
    CLAMAV_AVAILABLE = False
    logging.warning("Library 'pyclamd' tidak terinstal. Scan ClamAV akan dinonaktifkan.")

# Support untuk multiple config path
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

# Menggunakan konfigurasi terpusat untuk log file
LOG_FILE = config.get("ERADICATION_LOG_FILE", "/var/log/soc-incident-response/eradication.log")

try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}", file=sys.stderr)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('soc_eradication')

class MISPIntegration:
    """Kelas untuk integrasi dengan MISP platform."""
    
    def __init__(self, config):
        self.config = config
        self.misp_url = config.get('MISP_URL', 'https://192.168.28.135')
        self.misp_key = config.get('MISP_KEY', '')
        self.misp_verify_cert = config.get('MISP_VERIFY_CERT', 'false').lower() == 'true'
        
        # Headers untuk API MISP - PERBAIKAN: Gunakan format yang benar
        self.headers = {
            'Authorization': f'Bearer {self.misp_key}',  # PERBAIKAN: Tambahkan 'Bearer'
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        logger.info(f"MISP Integration diinisialisasi - URL: {self.misp_url}")
    
    def get_misp_iocs(self, event_id=None, days_back=7):
        """Mengambil IoC dari MISP platform."""
        try:
            # Jika tidak ada event_id, ambil semua IoC dari beberapa hari terakhir
            if event_id:
                url = f"{self.misp_url}/attributes/restSearch"
                payload = {
                    "eventid": event_id,
                    "returnFormat": "json"
                }
            else:
                url = f"{self.misp_url}/attributes/restSearch"
                payload = {
                    "returnFormat": "json",
                    "timestamp": f"{days_back}d"
                }
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                verify=self.misp_verify_cert,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'response' in data and 'Attribute' in data['response']:
                    iocs = data['response']['Attribute']
                    logger.info(f"Berhasil mengambil {len(iocs)} IoC dari MISP")
                    return iocs
                else:
                    logger.warning("Tidak ada IoC ditemukan di MISP")
                    return []
            else:
                logger.error(f"Error mengambil IoC dari MISP: HTTP {response.status_code} - {response.text}")
                return []
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error koneksi ke MISP: {e}")
            return []
        except Exception as e:
            logger.error(f"Error tidak terduga saat mengambil IoC dari MISP: {e}")
            return []
    
    def get_misp_indicators(self, ioc_type=None):
        """Mengambil indikator spesifik dari MISP."""
        try:
            url = f"{self.misp_url}/attributes/restSearch"
            payload = {
                "returnFormat": "json",
                "timestamp": "7d"
            }
            
            if ioc_type:
                payload["type"] = ioc_type
            
            response = requests.post(
                url,
                headers=self.headers,
                json=payload,
                verify=self.misp_verify_cert,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'response' in data and 'Attribute' in data['response']:
                    indicators = data['response']['Attribute']
                    logger.info(f"Berhasil mengambil {len(indicators)} indikator {ioc_type or 'semua'} dari MISP")
                    return indicators
                else:
                    logger.warning(f"Tidak ada indikator {ioc_type or 'semua'} ditemukan di MISP")
                    return []
            else:
                logger.error(f"Error mengambil indikator dari MISP: HTTP {response.status_code} - {response.text}")
                return []
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error koneksi ke MISP: {e}")
            return []
        except Exception as e:
            logger.error(f"Error tidak terduga saat mengambil indikator dari MISP: {e}")
            return []

def calculate_entropy(file_path):
    """Menghitung entropy dari file untuk deteksi encoding/encryption."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(1024)  # Baca 1KB pertama
        
        if not data:
            return 0.0
        
        # Hitung frekuensi byte
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Hitung entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    except Exception as e:
        logger.error(f"Error menghitung entropy untuk {file_path}: {e}")
        return 0.0

def extract_file_metadata(file_path):
    """Mengekstrak metadata dari file."""
    metadata = {
        'file_path': file_path,
        'file_name': os.path.basename(file_path),
        'file_size': 0,
        'file_type': 'unknown',
        'mime_type': 'unknown',
        'md5_hash': '',
        'sha256_hash': '',
        'entropy': 0.0,
        'creation_time': None,
        'modification_time': None,
        'access_time': None
    }
    
    try:
        # File size
        metadata['file_size'] = os.path.getsize(file_path)
        
        # File times
        stat_info = os.stat(file_path)
        metadata['creation_time'] = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
        metadata['modification_time'] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
        metadata['access_time'] = datetime.fromtimestamp(stat_info.st_atime).isoformat()
        
        # File type detection
        if magic:
            try:
                metadata['mime_type'] = magic.from_file(file_path, mime=True)
                metadata['file_type'] = magic.from_file(file_path)
            except Exception as e:
                logger.warning(f"Error deteksi tipe file untuk {file_path}: {e}")
        
        # Calculate hashes
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                metadata['md5_hash'] = hashlib.md5(data).hexdigest()
                metadata['sha256_hash'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.warning(f"Error menghitung hash untuk {file_path}: {e}")
        
        # Calculate entropy
        metadata['entropy'] = calculate_entropy(file_path)
        
    except Exception as e:
        logger.error(f"Error mengekstrak metadata untuk {file_path}: {e}")
    
    return metadata

class EradicationManager:
    """
    Manager untuk fase eradication - menghilangkan ancaman dari sistem
    """
    
    def __init__(self):
        self.config = self._load_config()
        # Menggunakan konfigurasi terpusat
        self.quarantine_dir = self.config.get("QUARANTINE_DIR", "/var/soc-quarantine")
        self.yara_rules_dir = self.config.get("YARA_RULES_DIR", "/var/ossec/etc/rules/yara")
        self.clamd_socket_path = self.config.get("CLAMD_SOCKET", "/var/run/clamav/clamd.ctl")
        self.web_dir = self.config.get("WEB_DIR", "/var/www/html")

        # Menggunakan pattern dari konfigurasi terpusat
        suspicious_patterns_str = self.config.get("ERADICATION_SUSPICIOUS_PATTERNS")
        if suspicious_patterns_str:
            self.suspicious_patterns = [p.strip() for p in suspicious_patterns_str.split('|||')]
        else:
            # Fallback patterns jika tidak ada di konfigurasi
            # Pola fallback jika tidak ada di konfigurasi (diperbaiki: kurung siku pada list sudah benar, escape karakter pada regex sudah benar)
            self.suspicious_patterns = [
                r'(?i)(eval\s*\(\s*base64_decode\s*\()',
                r'(?i)(passthru\s*\()',
                r'(?i)(shell_exec\s*\()',
                r'(?i)(system\s*\()',
                r'(?i)(exec\s*\()',
                r'(?i)(preg_replace\s*\(.*\/e\s*\))',
                r'(?i)(FilesMan|phpfm|P\.A\.S\.|\bWebShell\b|r57shell|c99shell)',
                r'(?i)(document\.write\s*\(\s*unescape\s*\()',
                r'(?i)(<iframe\s*src\s*=\s*["\']javascript:)',
                r'(?i)(fsockopen|pfsockopen)\s*\('
            ]

        # Inisialisasi MISP integration
        self.misp_integration = MISPIntegration(self.config)
        
        # Setup quarantine directory
        self.setup_quarantine_dir()
        
        # Check tool availability
        self.clamav_available = self._check_clamav_availability()
        self.yara_available = self._check_yara_availability()
        
        logger.info("EradicationManager diinisialisasi")

    @staticmethod
    def calculate_file_hash_static(file_path, hash_alg="sha256"):
        """Static method untuk menghitung hash file."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                if hash_alg.lower() == "md5":
                    return hashlib.md5(data).hexdigest()
                elif hash_alg.lower() == "sha1":
                    return hashlib.sha1(data).hexdigest()
                else:
                    return hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"Error menghitung hash {hash_alg} untuk {file_path}: {e}")
            return None

    def calculate_file_hash(self, file_path, hash_alg="sha256"):
        """Menghitung hash file."""
        return self.calculate_file_hash_static(file_path, hash_alg)

    def _load_config(self):
        """Memuat konfigurasi dari file terpusat."""
        config = {}
        config_file = None
        
        # Cari config file yang ada
        for cf in CONFIG_FILES:
            if os.path.exists(cf):
                config_file = cf
                break
        
        if not config_file:
            logger.error(f"File konfigurasi tidak ditemukan di: {', '.join(CONFIG_FILES)}")
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
            logger.info(f"Konfigurasi dimuat dari: {config_file}")
        except Exception as e:
            logger.error(f"Error membaca file konfigurasi {config_file}: {e}")
        return config

    def _check_clamav_availability(self):
        """Memeriksa ketersediaan ClamAV."""
        try:
            if pyclamd:
                cd = pyclamd.ClamdUnixSocket(self.clamd_socket_path)
                cd.ping()
                logger.info("ClamAV tersedia dan berfungsi")
                return True
            else:
                logger.warning("Library pyclamd tidak tersedia")
                return False
        except Exception as e:
            logger.warning(f"ClamAV tidak tersedia: {e}")
            return False

    def _check_yara_availability(self):
        """Memeriksa ketersediaan YARA."""
        try:
            if yara:
                # Test compile a simple rule
                test_rule = yara.compile(source='rule test { condition: true }')
                logger.info("YARA tersedia dan berfungsi")
                return True
            else:
                logger.warning("Library yara-python tidak tersedia")
                return False
        except Exception as e:
            logger.warning(f"YARA tidak tersedia: {e}")
            return False

    def setup_quarantine_dir(self):
        """Setup direktori karantina."""
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            logger.info(f"Direktori karantina siap: {self.quarantine_dir}")
        except Exception as e:
            logger.error(f"Error setup direktori karantina: {e}")

    def scan_with_clamav(self, file_path):
        """Scan file dengan ClamAV."""
        if not self.clamav_available:
            return False, "ClamAV tidak tersedia"
        
        try:
            cd = pyclamd.ClamdUnixSocket(self.clamd_socket_path)
            scan_result = cd.scan_file(file_path)
            
            if scan_result and file_path in scan_result:
                virus_name = scan_result[file_path][1]
                if virus_name:
                    return True, f"Virus terdeteksi: {virus_name}"
            
            return False, "Tidak ada virus terdeteksi"
        except Exception as e:
            logger.error(f"Error scan ClamAV untuk {file_path}: {e}")
            return False, f"Error scan ClamAV: {e}"

    def scan_with_yara(self, file_path):
        """Scan file dengan YARA rules."""
        if not self.yara_available:
            return False, "YARA tidak tersedia"
        
        try:
            matches = []
            
            # Scan dengan rules dari direktori YARA
            if os.path.exists(self.yara_rules_dir):
                for rule_file in os.listdir(self.yara_rules_dir):
                    if rule_file.endswith('.yar') or rule_file.endswith('.yara'):
                        rule_path = os.path.join(self.yara_rules_dir, rule_file)
                        try:
                            rules = yara.compile(rule_path)
                            rule_matches = rules.match(file_path)
                            if rule_matches:
                                matches.extend(rule_matches)
                        except Exception as e:
                            logger.warning(f"Error loading YARA rule {rule_path}: {e}")
            
            if matches:
                match_names = [match.rule for match in matches]
                return True, f"YARA match: {', '.join(match_names)}"
            
            return False, "Tidak ada YARA match"
        except Exception as e:
            logger.error(f"Error scan YARA untuk {file_path}: {e}")
            return False, f"Error scan YARA: {e}"

    def check_suspicious_content(self, file_path):
        """Memeriksa konten mencurigakan dalam file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for pattern in self.suspicious_patterns:
                if re.search(pattern, content):
                    return True, f"Pattern mencurigakan terdeteksi: {pattern}"
            
            return False, "Tidak ada konten mencurigakan"
        except Exception as e:
            logger.error(f"Error memeriksa konten mencurigakan untuk {file_path}: {e}")
            return False, f"Error pemeriksaan konten: {e}"

    def quarantine_file(self, file_path, detection_reason="Unknown"):
        """Memindahkan file ke karantina."""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File tidak ditemukan untuk karantina: {file_path}")
                return False, "File tidak ditemukan"
            
            # Generate quarantine filename
            file_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{file_name}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create metadata file
            metadata = {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'detection_reason': detection_reason,
                'quarantine_time': datetime.now().isoformat(),
                'file_hash': self.calculate_file_hash(quarantine_path),
                'file_metadata': extract_file_metadata(quarantine_path)
            }
            
            metadata_file = f"{quarantine_path}.meta"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"File berhasil dikarantina: {file_path} -> {quarantine_path}")
            return True, f"File dikarantina: {quarantine_path}"
            
        except Exception as e:
            logger.error(f"Error mengkarantina file {file_path}: {e}")
            return False, f"Error karantina: {e}"

    def _perform_all_scans_on_file(self, file_path):
        """Melakukan semua scan pada file."""
        scan_results = []
        
        # ClamAV scan
        is_malicious, reason = self.scan_with_clamav(file_path)
        if is_malicious:
            scan_results.append(('clamav', reason))
        
        # YARA scan
        is_malicious, reason = self.scan_with_yara(file_path)
        if is_malicious:
            scan_results.append(('yara', reason))
        
        # Suspicious content check
        is_malicious, reason = self.check_suspicious_content(file_path)
        if is_malicious:
            scan_results.append(('content', reason))
        
        return scan_results

    def scan_directory(self, directory_to_scan):
        """Scan seluruh direktori untuk ancaman."""
        logger.info(f"Memulai scan eradikasi untuk direktori: {directory_to_scan}")
        
        if not os.path.exists(directory_to_scan):
            logger.error(f"Direktori tidak ditemukan: {directory_to_scan}")
            return False, "Direktori tidak ditemukan"
        
        scanned_files = 0
        quarantined_files = 0
        scan_results = []
        
        # Get MISP IoCs untuk referensi
        misp_iocs = self.misp_integration.get_misp_iocs()
        misp_hashes = set()
        misp_ips = set()
        
        # Extract hashes dan IPs dari MISP IoCs
        for ioc in misp_iocs:
            if ioc.get('type') in ['md5', 'sha1', 'sha256']:
                misp_hashes.add(ioc.get('value', '').lower())
            elif ioc.get('type') in ['ip-src', 'ip-dst']:
                misp_ips.add(ioc.get('value', ''))
        
        logger.info(f"Menggunakan {len(misp_hashes)} hash dan {len(misp_ips)} IP dari MISP")
        
        for root, dirs, files in os.walk(directory_to_scan):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                scanned_files += 1
                
                try:
                    # Skip files that are too large (> 100MB)
                    if os.path.getsize(file_path) > 100 * 1024 * 1024:
                        logger.debug(f"Skip file terlalu besar: {file_path}")
                        continue
                    
                    # Check file hash against MISP IoCs
                    file_hash = self.calculate_file_hash(file_path, 'sha256')
                    if file_hash and file_hash.lower() in misp_hashes:
                        logger.warning(f"File hash match dengan MISP IoC: {file_path}")
                        success, reason = self.quarantine_file(file_path, f"MISP IoC match: {file_hash}")
                        if success:
                            quarantined_files += 1
                            scan_results.append({
                                'file': file_path,
                                'detection': 'misp_hash',
                                'reason': f"MISP IoC match: {file_hash}"
                            })
                        continue
                    
                    # Perform all scans
                    scan_detections = self._perform_all_scans_on_file(file_path)
                    
                    if scan_detections:
                        detection_reasons = [f"{scan_type}: {reason}" for scan_type, reason in scan_detections]
                        combined_reason = "; ".join(detection_reasons)
                        
                        success, reason = self.quarantine_file(file_path, combined_reason)
                        if success:
                            quarantined_files += 1
                            scan_results.append({
                                'file': file_path,
                                'detection': 'scan',
                                'reason': combined_reason
                            })
                
                except Exception as e:
                    logger.error(f"Error scanning file {file_path}: {e}")
        
        logger.info(f"Scan eradikasi selesai. {scanned_files} file di-scan, {quarantined_files} file dikarantina")
        
        return True, {
            'scanned_files': scanned_files,
            'quarantined_files': quarantined_files,
            'scan_results': scan_results,
            'misp_iocs_used': len(misp_hashes) + len(misp_ips)
        }

    def process_wazuh_alert(self, alert_data_str):
        """Memproses alert Wazuh untuk eradikasi dengan input dari Deteksi-IoC.py."""
        try:
            # Parse input data yang berisi alert dan ioc_data
            input_data = json.loads(alert_data_str)
            
            # Extract alert dan ioc_data
            alert_data = input_data.get('alert', {})
            ioc_data = input_data.get('ioc_data', {})
            
            logger.info(f"Memproses alert Wazuh untuk eradikasi: {alert_data.get('id', 'unknown')}")
            logger.info(f"Menggunakan IoC data dari Deteksi-IoC.py: {len(ioc_data.get('ioc_data', []))} IoC")
            
            # Extract target files dari alert dan ioc_data
            target_files = set()
            
            # Dari alert data
            if 'data' in alert_data:
                for data_item in alert_data['data']:
                    if 'file' in data_item:
                        target_files.add(data_item['file'])
            
            # Dari ioc_data
            if 'ioc_data' in ioc_data:
                for ioc in ioc_data['ioc_data']:
                    if 'target_file' in ioc and ioc['target_file']:
                        target_files.add(ioc['target_file'])
            
            if not target_files:
                logger.warning("Tidak ada target file yang ditemukan")
                return False, "Tidak ada target file yang ditemukan"
            
            logger.info(f"Target files untuk eradikasi: {list(target_files)}")
            
            # Process each target file
            processed_files = 0
            quarantined_files = 0
            results = []
            
            for target_file in target_files:
                if os.path.exists(target_file):
                    logger.info(f"Melakukan eradikasi pada file: {target_file}")
                    
                    # Perform scans on target file
                    scan_detections = self._perform_all_scans_on_file(target_file)
                    
                    if scan_detections:
                        detection_reasons = [f"{scan_type}: {reason}" for scan_type, reason in scan_detections]
                        combined_reason = "; ".join(detection_reasons)
                        
                        success, reason = self.quarantine_file(target_file, combined_reason)
                        if success:
                            quarantined_files += 1
                            results.append({
                                'file': target_file,
                                'action': 'quarantined',
                                'reason': combined_reason
                            })
                            logger.info(f"File berhasil dikarantina: {target_file}")
                        else:
                            results.append({
                                'file': target_file,
                                'action': 'failed',
                                'reason': reason
                            })
                            logger.error(f"Gagal mengkarantina file: {reason}")
                    else:
                        results.append({
                            'file': target_file,
                            'action': 'clean',
                            'reason': 'Tidak ada ancaman terdeteksi'
                        })
                        logger.info(f"Tidak ada ancaman terdeteksi pada file: {target_file}")
                    
                    processed_files += 1
                else:
                    logger.warning(f"Target file tidak ditemukan: {target_file}")
                    results.append({
                        'file': target_file,
                        'action': 'not_found',
                        'reason': 'File tidak ditemukan'
                    })
            
            # Summary
            summary = {
                'processed_files': processed_files,
                'quarantined_files': quarantined_files,
                'results': results,
                'ioc_data_used': len(ioc_data.get('ioc_data', []))
            }
            
            logger.info(f"Eradikasi selesai: {processed_files} file diproses, {quarantined_files} file dikarantina")
            return True, summary
                
        except json.JSONDecodeError as e:
            error_msg = f"Error parsing alert data: {e}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error memproses alert: {e}"
            logger.error(error_msg)
            return False, error_msg

def main():
    """Main function untuk eradikasi."""
    try:
        # Check if running with input from stdin (Wazuh integration)
        alert_data = None
        if not sys.stdin.isatty():
            try:
                alert_data = sys.stdin.read().strip()
                logger.info("Menerima alert data dari stdin")
            except Exception as e:
                logger.error(f"Error membaca dari stdin: {e}")
        
        eradication_manager = EradicationManager()
        
        if alert_data:
            # Process Wazuh alert dengan input dari Deteksi-IoC.py
            success, details = eradication_manager.process_wazuh_alert(alert_data)
            if success:
                logger.info(f"Eradikasi berhasil: {details}")
                print(f"SUCCESS: {json.dumps(details, indent=2)}")
            else:
                logger.error(f"Eradikasi gagal: {details}")
                print(f"ERROR: {details}")
        else:
            # Manual scan of web directory
            web_dir = eradication_manager.web_dir
            if os.path.exists(web_dir):
                success, results = eradication_manager.scan_directory(web_dir)
                if success:
                    logger.info(f"Scan eradikasi selesai: {results}")
                    print(f"SUCCESS: {json.dumps(results, indent=2)}")
                else:
                    logger.error(f"Scan eradikasi gagal: {results}")
                    print(f"ERROR: {results}")
            else:
                logger.error(f"Direktori web tidak ditemukan: {web_dir}")
                print(f"ERROR: Direktori web tidak ditemukan: {web_dir}")
    
    except Exception as e:
        logger.error(f"Error dalam main eradikasi: {e}")
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()
