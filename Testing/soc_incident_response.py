#!/usr/bin/env python3

"""
SOC Incident Response Lifecycle (IRLC) - NIST 800-61r2 Framework
Script integrasi utama untuk menangani insiden defacement secara otomatis
"""

import os
import sys
import json
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path

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

# Konfigurasi logging dari file terpusat
LOG_FILE = config.get("LOG_DIR", "/var/log/soc-incident-response") + "/soc_incident_response.log"
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log {os.path.dirname(LOG_FILE)}. Error: {e}", file=sys.stderr)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('soc_incident_response')

class SOCIncidentResponse:
    """
    Kelas utama untuk menangani insiden sesuai IRLC NIST 800-61r2
    """
    
    def __init__(self):
        self.config = config
        self.incident_id = None
        self.incident_start_time = None
        self.current_phase = None
        self.alert_data = None
        self.ioc_data = None
        
        # Path script untuk setiap fase
        self.scripts = {
            'detection': 'Deteksi.py',
            'containment': 'containment.py',
            'eradication': 'eradication.py',
            'recovery': 'restore.py',
            'post_incident': 'PostIA.py'
        }
        
        # Status setiap fase
        self.phase_status = {
            'detection': False,
            'containment': False,
            'eradication': False,
            'recovery': False,
            'post_incident': False
        }
        
        # Validasi script availability
        self._validate_scripts()
        
        logger.info("SOC Incident Response Manager diinisialisasi")

    def _validate_scripts(self):
        """Validasi ketersediaan semua script yang diperlukan."""
        missing_scripts = []
        for phase, script_name in self.scripts.items():
            script_path = os.path.join(os.path.dirname(__file__), script_name)
            if not os.path.exists(script_path):
                missing_scripts.append(script_name)
                logger.warning(f"Script {script_name} tidak ditemukan untuk fase {phase}")
        
        if missing_scripts:
            logger.warning(f"Script yang tidak ditemukan: {', '.join(missing_scripts)}")

    def generate_incident_id(self):
        """Generate ID unik untuk insiden."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.incident_id = f"INCIDENT_{timestamp}"
        return self.incident_id

    def log_incident_start(self, alert_data):
        """Mencatat dimulainya insiden."""
        self.incident_start_time = datetime.now()
        self.alert_data = alert_data
        
        logger.info(f"=== INSIDEN DIMULAI ===")
        logger.info(f"Incident ID: {self.incident_id}")
        logger.info(f"Start Time: {self.incident_start_time}")
        logger.info(f"Alert Data: {alert_data[:200]}...")

    def log_phase_completion(self, phase, success, details=""):
        """Mencatat penyelesaian fase."""
        self.phase_status[phase] = success
        self.current_phase = phase
        
        status = "BERHASIL" if success else "GAGAL"
        logger.info(f"=== FASE {phase.upper()} {status} ===")
        if details:
            logger.info(f"Detail: {details}")

    def run_script(self, script_name, input_data=None):
        """Menjalankan script sesuai fase IRLC"""
        try:
            script_path = self._get_script_path(script_name)
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"Script {script_name} tidak ditemukan: {script_path}")
            
            # Validasi permission script
            if not os.access(script_path, os.X_OK):
                os.chmod(script_path, 0o755)
                self.logger.warning(f"Permission script {script_name} telah diperbaiki")
            
            # Jalankan script dengan timeout
            result = subprocess.run(
                [sys.executable, script_path],
                input=input_data.encode() if input_data else None,
                capture_output=True,
                text=True,
                timeout=int(self.config.get('COMMAND_TIMEOUT', 300))
            )
            
            if result.returncode != 0:
                self.logger.error(f"Script {script_name} gagal: {result.stderr}")
                return False, result.stderr
            
            self.logger.info(f"Script {script_name} berhasil dijalankan")
            return True, result.stdout
            
        except subprocess.TimeoutExpired:
            error_msg = f"Script {script_name} timeout setelah {self.config.get('COMMAND_TIMEOUT', 300)} detik"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error menjalankan script {script_name}: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg

    def ensure_directories_exist(self):
        """Memastikan semua direktori yang diperlukan ada."""
        required_dirs = [
            self.config.get("QUARANTINE_DIR", "/var/soc-quarantine"),
            self.config.get("BACKUP_DIR", "/var/soc-backup"),
            self.config.get("LOG_DIR", "/var/log/soc-incident-response"),
            os.path.dirname(self.config.get("BLOCKED_IPS_FILE", "/var/log/soc-incident-response/blocked_ips.txt")),
            self.config.get("INCIDENT_REPORTS_DIR", "/var/log/soc-incident-response/reports")
        ]
        
        for directory in required_dirs:
            try:
                os.makedirs(directory, exist_ok=True)
                logger.info(f"Direktori {directory} siap")
            except Exception as e:
                logger.warning(f"Tidak dapat membuat direktori {directory}: {e}")

    def phase_preparation(self):
        """
        FASE PREPARATION - Persiapan sistem
        Sesuai NIST 800-61r2: Preparation Phase
        """
        logger.info("=== FASE PREPARATION ===")
        
        # Validasi konfigurasi
        required_configs = ["WEB_DIR", "BACKUP_DIR", "QUARANTINE_DIR"]
        missing_configs = []
        
        for config_key in required_configs:
            if not self.config.get(config_key):
                missing_configs.append(config_key)
        
        if missing_configs:
            error_msg = f"Konfigurasi yang diperlukan tidak ditemukan: {', '.join(missing_configs)}"
            logger.error(error_msg)
            return False, error_msg
        
        # Validasi direktori web
        web_dir = self.config.get("WEB_DIR")
        if not os.path.isdir(web_dir):
            error_msg = f"Direktori web tidak ditemukan: {web_dir}"
            logger.error(error_msg)
            return False, error_msg
        
        # Buat direktori yang diperlukan
        self.ensure_directories_exist()
        
        logger.info("Fase Preparation selesai")
        return True, "Preparation phase completed successfully"

    def phase_detection_analysis(self, alert_data):
        """
        FASE DETECTION & ANALYSIS - Deteksi dan analisis insiden
        Sesuai NIST 800-61r2: Detection & Analysis Phase
        """
        logger.info("=== FASE DETECTION & ANALYSIS ===")
        
        try:
            # Parse alert data
            alert = json.loads(alert_data)
            rule_id = str(alert.get('rule', {}).get('id', ''))
            description = alert.get('rule', {}).get('description', 'N/A')
            
            logger.info(f"Alert terdeteksi - Rule ID: {rule_id}, Deskripsi: {description}")
            
            # Jalankan script deteksi IoC
            success, details = self.run_script(self.scripts['detection'], alert_data)
            
            if success:
                logger.info("Deteksi IoC berhasil")
                self.log_phase_completion('detection', True, "IoC berhasil dideteksi")
                
                # Baca data IoC yang dihasilkan untuk digunakan fase berikutnya
                ioc_data_file = self.config.get('IOC_DATA_FILE', '/tmp/detected_ioc_data.json')
                if os.path.exists(ioc_data_file):
                    try:
                        with open(ioc_data_file, 'r') as f:
                            ioc_data = json.load(f)
                        logger.info(f"Data IoC berhasil dibaca: {len(ioc_data.get('ioc_data', []))} IoC")
                        self.ioc_data = ioc_data
                    except Exception as e:
                        logger.warning(f"Error membaca data IoC: {e}")
                        self.ioc_data = None
                else:
                    logger.warning("File data IoC tidak ditemukan")
                    self.ioc_data = None
                
                return True, "Detection & Analysis phase completed"
            else:
                logger.error(f"Deteksi IoC gagal: {details}")
                self.log_phase_completion('detection', False, details)
                return False, details
                
        except json.JSONDecodeError as e:
            error_msg = f"Format alert data tidak valid: {e}"
            logger.error(error_msg)
            self.log_phase_completion('detection', False, error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error dalam fase detection: {e}"
            logger.error(error_msg)
            self.log_phase_completion('detection', False, error_msg)
            return False, error_msg

    def phase_containment(self, alert_data):
        """
        FASE CONTAINMENT - Isolasi ancaman
        Sesuai NIST 800-61r2: Containment Phase
        """
        logger.info("=== FASE CONTAINMENT ===")
        
        try:
            # Siapkan data untuk containment (alert + IoC data)
            containment_data = {
                'alert': json.loads(alert_data) if isinstance(alert_data, str) else alert_data,
                'ioc_data': self.ioc_data
            }
            
            # Jalankan script containment dengan data lengkap
            success, details = self.run_script(self.scripts['containment'], json.dumps(containment_data))
            
            if success:
                logger.info("Containment berhasil")
                self.log_phase_completion('containment', True, "Ancaman berhasil diisolasi")
                return True, "Containment phase completed"
            else:
                logger.error(f"Containment gagal: {details}")
                self.log_phase_completion('containment', False, details)
                return False, details
                
        except Exception as e:
            error_msg = f"Error dalam fase containment: {e}"
            logger.error(error_msg)
            self.log_phase_completion('containment', False, error_msg)
            return False, error_msg

    def phase_eradication(self, alert_data):
        """
        FASE ERADICATION - Penghapusan ancaman
        Sesuai NIST 800-61r2: Eradication Phase
        """
        logger.info("=== FASE ERADICATION ===")
        
        try:
            # Siapkan data untuk eradication (alert + IoC data)
            eradication_data = {
                'alert': json.loads(alert_data) if isinstance(alert_data, str) else alert_data,
                'ioc_data': self.ioc_data
            }
            
            # Jalankan script eradication dengan data lengkap
            success, details = self.run_script(self.scripts['eradication'], json.dumps(eradication_data))
            
            if success:
                logger.info("Eradication berhasil")
                self.log_phase_completion('eradication', True, "Ancaman berhasil dihapus")
                return True, "Eradication phase completed"
            else:
                logger.error(f"Eradication gagal: {details}")
                self.log_phase_completion('eradication', False, details)
                return False, details
                
        except Exception as e:
            error_msg = f"Error dalam fase eradication: {e}"
            logger.error(error_msg)
            self.log_phase_completion('eradication', False, error_msg)
            return False, error_msg

    def phase_recovery(self, alert_data):
        """
        FASE RECOVERY - Pemulihan sistem
        Sesuai NIST 800-61r2: Recovery Phase
        """
        logger.info("=== FASE RECOVERY ===")
        
        try:
            # Siapkan data untuk recovery (alert + IoC data)
            recovery_data = {
                'alert': json.loads(alert_data) if isinstance(alert_data, str) else alert_data,
                'ioc_data': self.ioc_data
            }
            
            # Jalankan script recovery dengan data lengkap
            success, details = self.run_script(self.scripts['recovery'], json.dumps(recovery_data))
            
            if success:
                logger.info("Recovery berhasil")
                self.log_phase_completion('recovery', True, "Sistem berhasil dipulihkan")
                return True, "Recovery phase completed"
            else:
                logger.error(f"Recovery gagal: {details}")
                self.log_phase_completion('recovery', False, details)
                return False, details
                
        except Exception as e:
            error_msg = f"Error dalam fase recovery: {e}"
            logger.error(error_msg)
            self.log_phase_completion('recovery', False, error_msg)
            return False, error_msg

    def phase_post_incident(self, alert_data):
        """
        FASE POST-INCIDENT ACTIVITY - Dokumentasi dan analisis
        Sesuai NIST 800-61r2: Post-Incident Activity Phase
        """
        logger.info("=== FASE POST-INCIDENT ACTIVITY ===")
        
        try:
            # Siapkan data untuk post-incident (alert + IoC data)
            post_incident_data = {
                'alert': json.loads(alert_data) if isinstance(alert_data, str) else alert_data,
                'ioc_data': self.ioc_data
            }
            
            # Jalankan script MISP untuk threat intelligence
            success, details = self.run_script(self.scripts['post_incident'], json.dumps(post_incident_data))
            
            if success:
                logger.info("Post-incident activity berhasil")
                self.log_phase_completion('post_incident', True, "Threat intelligence berhasil dikirim")
            else:
                logger.warning(f"Post-incident activity gagal: {details}")
                self.log_phase_completion('post_incident', False, details)
            
            # Buat laporan insiden
            self.create_incident_report()
            
            return True, "Post-incident activity completed"
                
        except Exception as e:
            error_msg = f"Error dalam fase post-incident: {e}"
            logger.error(error_msg)
            self.log_phase_completion('post_incident', False, error_msg)
            return False, error_msg

    def create_incident_report(self):
        """Membuat laporan insiden lengkap."""
        try:
            reports_dir = self.config.get("INCIDENT_REPORTS_DIR", "/var/log/soc-incident-response/reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            report_file = os.path.join(reports_dir, f"{self.incident_id}_report.json")
            
            report_data = {
                "incident_id": self.incident_id,
                "start_time": self.incident_start_time.isoformat() if self.incident_start_time else None,
                "end_time": datetime.now().isoformat(),
                "alert_data": self.alert_data,
                "phase_status": self.phase_status,
                "config_used": {
                    "web_dir": self.config.get("WEB_DIR"),
                    "backup_dir": self.config.get("BACKUP_DIR"),
                    "quarantine_dir": self.config.get("QUARANTINE_DIR")
                }
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"Laporan insiden dibuat: {report_file}")
            
        except Exception as e:
            logger.error(f"Gagal membuat laporan insiden: {e}")

    def process_incident(self, alert_data):
        """
        Memproses insiden lengkap sesuai IRLC NIST 800-61r2
        """
        try:
            # Generate incident ID
            self.generate_incident_id()
            self.log_incident_start(alert_data)
            
            # FASE 1: PREPARATION
            success, details = self.phase_preparation()
            if not success:
                logger.error(f"Fase Preparation gagal: {details}")
                return False
            
            # FASE 2: DETECTION & ANALYSIS
            success, details = self.phase_detection_analysis(alert_data)
            if not success:
                logger.error(f"Fase Detection & Analysis gagal: {details}")
                # Lanjutkan ke containment meskipun detection gagal
            
            # FASE 3: CONTAINMENT
            success, details = self.phase_containment(alert_data)
            if not success:
                logger.error(f"Fase Containment gagal: {details}")
                # Lanjutkan ke eradication meskipun containment gagal
            
            # FASE 4: ERADICATION
            success, details = self.phase_eradication(alert_data)
            if not success:
                logger.error(f"Fase Eradication gagal: {details}")
                # Lanjutkan ke recovery meskipun eradication gagal
            
            # FASE 5: RECOVERY
            success, details = self.phase_recovery(alert_data)
            if not success:
                logger.error(f"Fase Recovery gagal: {details}")
                # Lanjutkan ke post-incident meskipun recovery gagal
            
            # FASE 6: POST-INCIDENT ACTIVITY
            success, details = self.phase_post_incident(alert_data)
            if not success:
                logger.error(f"Fase Post-Incident Activity gagal: {details}")
            
            # Log penyelesaian insiden
            incident_end_time = datetime.now()
            duration = incident_end_time - self.incident_start_time if self.incident_start_time else None
            
            logger.info("=== INSIDEN SELESAI ===")
            logger.info(f"Incident ID: {self.incident_id}")
            logger.info(f"End Time: {incident_end_time}")
            if duration:
                logger.info(f"Duration: {duration}")
            logger.info(f"Final Status: {self.phase_status}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error dalam pemrosesan insiden: {e}")
            return False

def main():
    """Main function untuk Active Response dari Wazuh."""
    try:
        # Inisialisasi SOC Incident Response Manager
        soc_ir = SOCIncidentResponse()
        
        # Cek apakah ada argumen untuk operasi manual
        if len(sys.argv) > 1:
            command = sys.argv[1].lower()
            
            if command == "test":
                # Test mode dengan sample alert
                sample_alert = {
                    "rule": {
                        "id": "550",
                        "description": "Web defacement detected"
                    },
                    "data": {
                        "srcip": "192.168.1.100"
                    },
                    "syscheck": {
                        "path": "/var/www/html/index.html"
                    }
                }
                alert_data = json.dumps(sample_alert)
                success = soc_ir.process_incident(alert_data)
                sys.exit(0 if success else 1)
                
            elif command == "status":
                # Tampilkan status sistem
                print("=== SOC INCIDENT RESPONSE STATUS ===")
                print(f"Config loaded: {'Yes' if soc_ir.config else 'No'}")
                print(f"Web directory: {soc_ir.config.get('WEB_DIR', 'Not set')}")
                print(f"Backup directory: {soc_ir.config.get('BACKUP_DIR', 'Not set')}")
                print(f"Quarantine directory: {soc_ir.config.get('QUARANTINE_DIR', 'Not set')}")
                sys.exit(0)
                
            else:
                logger.error(f"Command tidak dikenali: {command}")
                print("Usage: soc_incident_response.py [test|status]")
                sys.exit(1)
        
        # Mode Wazuh Active Response - baca alert dari stdin
        logger.info("Menunggu data alert dari Wazuh Active Response...")
        
        try:
            alert_data = sys.stdin.read().strip()
            if not alert_data:
                logger.error("Tidak ada data alert yang diterima dari stdin.")
                sys.exit(1)
                
            logger.info(f"Data alert diterima: {alert_data[:100]}...")
            
            # Proses insiden lengkap
            success = soc_ir.process_incident(alert_data)
            sys.exit(0 if success else 1)
            
        except Exception as e:
            logger.error(f"Error membaca alert data dari stdin: {e}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error dalam main function: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main() 