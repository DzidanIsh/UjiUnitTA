#!/usr/bin/env python3

"""
SOC Unified Restore Script - NIST 800-61 Incident Response Framework
Recovery Phase: Restore sistem dari backup (Auto & Manual Mode)

Fitur:
- Auto Restore: Berdasarkan Wazuh alert (Active Response)
- Manual Restore: Interaktif dengan user confirmation
- Git Repository Management
- Dynamic File Restore
- Remote Backup Support
- Comprehensive Logging
"""

import os
import sys
import json
import logging
import subprocess
import time
import argparse
import base64
import getpass
import datetime
import shutil
import glob
import tarfile
from datetime import datetime
from pathlib import Path

# Import Git library dengan error handling
try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    git = None
    GIT_AVAILABLE = False
    print("Warning: Library 'gitpython' tidak tersedia. Git restore akan dinonaktifkan.")

# Support untuk multiple config path
CONFIG_FILES = ["/etc/soc-config/config.conf", "/etc/web-backup/config.conf"]

# Warna untuk output terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    YELLOW = '\033[33m'

def load_config():
    """Memuat konfigurasi dari file terpusat."""
    config = {}
    config_file = None
    
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

# Konfigurasi logging
LOG_FILE = config.get("RESTORE_LOG_FILE", "/var/log/wazuh/active-response/restore.log")
AUTO_LOG_FILE = config.get("RESTORE_AUTO_LOG_FILE", "/var/log/wazuh/active-response/restore_auto.log")

try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(AUTO_LOG_FILE), exist_ok=True)
except OSError as e:
    print(f"Warning: Tidak dapat membuat direktori log. Error: {e}", file=sys.stderr)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.FileHandler(AUTO_LOG_FILE)
    ]
)
logger = logging.getLogger('soc_restore_unified')

def print_banner():
    """Menampilkan banner aplikasi"""
    banner = """
=================================================================
         SOC UNIFIED RESTORE - NIST 800-61 RECOVERY PHASE
=================================================================
    """
    print(Colors.HEADER + banner + Colors.ENDC)

def error_exit(message):
    """Menampilkan pesan error dan keluar"""
    print(Colors.FAIL + f"ERROR: {message}" + Colors.ENDC, file=sys.stderr)
    logger.error(f"FATAL ERROR: {message}")
    sys.exit(1)

def success_msg(message, is_automated_call=False):
    """Menampilkan pesan sukses"""
    if not is_automated_call:
        print(Colors.GREEN + f"SUCCESS: {message}" + Colors.ENDC)
    logger.info(f"SUCCESS: {message}")

def info_msg(message, is_automated_call=False):
    """Menampilkan pesan info"""
    if not is_automated_call:
        print(Colors.BLUE + f"INFO: {message}" + Colors.ENDC)
    logger.info(f"INFO: {message}")

def warning_msg(message, is_automated_call=False):
    """Menampilkan pesan peringatan"""
    if not is_automated_call:
        print(Colors.WARNING + f"WARNING: {message}" + Colors.ENDC)
    logger.warning(f"WARNING: {message}")

class UnifiedRestoreManager:
    def __init__(self, mode="manual"):
        self.mode = mode
        self.config = self._load_config()
        
        # Konfigurasi dari file config terpusat
        self.web_dir = self.config.get("WEB_DIR", "/var/www/html")
        self.backup_dir = self.config.get("BACKUP_DIR", "/var/soc-backup")
        self.monitoring_user = self.config.get("MONITORING_USER", "soc-backup")
        self.monitoring_server = self.config.get("MONITORING_SERVER", "")
        self.monitoring_password = self.config.get("MONITORING_PASSWORD", "")
        
        # Path backup lokal dan remote
        self.local_backup_path = os.path.join(self.backup_dir, "local")
        self.remote_backup_path = self.config.get("REMOTE_BACKUP_PATH", "/home/soc-backup/backups")
        
        # Konteks alert saat ini (untuk auto mode)
        self.current_alert_context = {}
        
        # Validasi konfigurasi
        self._validate_config()

    def _load_config(self):
        """Memuat konfigurasi dari file."""
        config = {}
        config_file = None
        
        for cf in CONFIG_FILES:
            if os.path.exists(cf):
                config_file = cf
                break
        
        if not config_file:
            error_exit(f"File konfigurasi tidak ditemukan di: {', '.join(CONFIG_FILES)}")

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
            error_exit(f"Error membaca file konfigurasi {config_file}: {e}")
        
        return config

    def _validate_config(self):
        """Validasi konfigurasi yang diperlukan."""
        required_configs = ["WEB_DIR", "BACKUP_DIR"]
        missing_configs = []
        
        for config_key in required_configs:
            if not self.config.get(config_key):
                missing_configs.append(config_key)
        
        if missing_configs:
            error_exit(f"Konfigurasi yang diperlukan tidak ditemukan: {', '.join(missing_configs)}")
        
        if not os.path.exists(self.web_dir):
            error_exit(f"Direktori web tidak ditemukan: {self.web_dir}")
        
        logger.info("Validasi konfigurasi berhasil")

    def _run_command(self, command, timeout=300):
        """Menjalankan command dengan timeout."""
        try:
            logger.debug(f"Menjalankan command: {command}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                logger.debug(f"Command berhasil: {command}")
                return True, result.stdout
            else:
                logger.error(f"Command gagal: {command}")
                logger.error(f"Error output: {result.stderr}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {command}")
            return False, "Command timeout"
        except Exception as e:
            logger.error(f"Error menjalankan command {command}: {e}")
            return False, str(e)

    def process_wazuh_alert(self, alert_data_str):
        """Proses alert dari Wazuh untuk auto restore."""
        logger.info("Menerima data alert dari Wazuh untuk auto restore.")
        
        try:
            # Parse input data
            input_data = json.loads(alert_data_str)
            
            # Cek apakah ini data lengkap dengan IoC atau alert langsung
            if isinstance(input_data, dict) and 'alert' in input_data and 'ioc_data' in input_data:
                alert = input_data['alert']
                ioc_data = input_data['ioc_data']
                logger.info("Memproses data lengkap dengan IoC untuk auto restore")
            else:
                alert = input_data
                ioc_data = None
                logger.debug(f"Data alert yang di-parse: {alert}")
            
            self.current_alert_context = alert
        
        except json.JSONDecodeError as e:
            logger.error(f"Format data alert Wazuh tidak valid: {e}. Data: {alert_data_str[:200]}...")
            return False
        
        rule_id = str(alert.get('rule', {}).get('id', ''))
        file_path = alert.get('syscheck', {}).get('path')
        description = alert.get('rule', {}).get('description', 'N/A')
        
        logger.info(f"Memproses alert auto restore - Rule ID: {rule_id}, File: {file_path}, Deskripsi: {description}")
        
        # Ambil rule IDs dari konfigurasi untuk auto restore
        restore_rule_ids = self.config.get("RESTORE_RULE_IDS", "100010,100011,100012").split(',')
        restore_rule_ids = [rid.strip() for rid in restore_rule_ids]
        
        if rule_id in restore_rule_ids:
            logger.info(f"Rule ID {rule_id} memicu auto restore")
            
            # Tentukan sumber backup berdasarkan rule ID
            backup_source = "local"
            if rule_id in ["100011", "100012"]:
                backup_source = "remote"
            
            # Lakukan auto restore
            success = self._perform_auto_restore(backup_source)
            
            if success:
                logger.info(f"Auto restore berhasil dari {backup_source} backup")
                return True
            else:
                logger.error(f"Auto restore gagal dari {backup_source} backup")
                return False
        else:
            logger.info(f"Rule ID {rule_id} tidak memicu auto restore")
            return False

    def _perform_auto_restore(self, backup_source):
        """Melakukan auto restore dari sumber yang ditentukan."""
        try:
            logger.info(f"Memulai auto restore dari sumber: {backup_source}")
            
            # Cari backup terbaru
            backup_path = self._find_latest_backup(backup_source)
            if not backup_path:
                logger.error(f"Tidak dapat menemukan backup untuk restore dari sumber: {backup_source}")
                return False
            
            # Lakukan restore
            success = self._perform_restore(backup_path)
            
            if success:
                logger.info(f"Auto restore berhasil dari {backup_source} backup: {backup_path}")
                return True
            else:
                logger.error(f"Auto restore gagal dari {backup_source} backup: {backup_path}")
                return False
                
        except Exception as e:
            logger.error(f"Error saat auto restore: {e}")
            return False

    def _find_latest_backup(self, backup_source="local"):
        """Mencari backup terbaru dari sumber yang ditentukan."""
        try:
            if backup_source == "local":
                if not os.path.exists(self.local_backup_path):
                    logger.error(f"Direktori backup lokal tidak ditemukan: {self.local_backup_path}")
                    return None
                
                backup_files = glob.glob(os.path.join(self.local_backup_path, "*.tar.gz"))
                if not backup_files:
                    logger.error("Tidak ada file backup lokal yang ditemukan")
                    return None
                
                latest_backup = max(backup_files, key=os.path.getctime)
                logger.info(f"Backup lokal terbaru ditemukan: {latest_backup}")
                return latest_backup
                
            elif backup_source == "remote":
                if not self.monitoring_server:
                    logger.error("Server monitoring tidak dikonfigurasi")
                    return None
                
                remote_backups = self._get_remote_backup_list()
                if not remote_backups:
                    logger.error("Tidak ada backup remote yang ditemukan")
                    return None
                
                latest_backup = remote_backups[-1]
                logger.info(f"Backup remote terbaru ditemukan: {latest_backup}")
                return latest_backup
                
            else:
                logger.error(f"Sumber backup tidak valid: {backup_source}")
                return None
                
        except Exception as e:
            logger.error(f"Error mencari backup terbaru: {e}")
            return None

    def _get_remote_backup_list(self):
        """Mendapatkan daftar backup dari server remote."""
        try:
            if not self.monitoring_server or not self.monitoring_user:
                logger.error("Konfigurasi server monitoring tidak lengkap")
                return []
            
            command = f"ssh {self.monitoring_user}@{self.monitoring_server} 'ls -t {self.remote_backup_path}/*.tar.gz 2>/dev/null'"
            
            success, output = self._run_command(command)
            
            if success:
                backup_files = [line.strip() for line in output.split('\n') if line.strip()]
                logger.info(f"Ditemukan {len(backup_files)} backup remote")
                return backup_files
            else:
                logger.error(f"Gagal mendapatkan daftar backup remote: {output}")
                return []
                
        except Exception as e:
            logger.error(f"Error mendapatkan daftar backup remote: {e}")
            return []

    def _perform_restore(self, backup_path):
        """Melakukan restore dari backup path."""
        try:
            logger.info(f"Memulai restore dari: {backup_path}")
            
            # Buat pre-restore backup
            self._create_pre_restore_backup()
            
            # Backup path bisa berupa file tar.gz atau direktori
            if backup_path.endswith('.tar.gz'):
                success, output = self._run_command(f"tar -xzf {backup_path} -C {self.web_dir} --strip-components=1")
                if not success:
                    logger.error(f"Gagal extract backup file: {output}")
                    return False
            else:
                success, output = self._run_command(f"cp -r {backup_path}/* {self.web_dir}/")
                if not success:
                    logger.error(f"Gagal copy backup direktori: {output}")
                    return False
            
            # Set permission yang benar
            self._set_web_permissions()
            
            # Verifikasi restore
            if self._verify_restore():
                logger.info("Restore berhasil dan terverifikasi")
                return True
            else:
                logger.error("Restore gagal verifikasi")
                return False
                
        except Exception as e:
            logger.error(f"Error saat melakukan restore: {e}")
            return False

    def _create_pre_restore_backup(self):
        """Membuat backup dari kondisi saat ini sebelum restore."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"pre_restore_backup_{timestamp}"
            backup_path = os.path.join(self.backup_dir, backup_name)
            
            logger.info(f"Membuat pre-restore backup: {backup_path}")
            
            os.makedirs(backup_path, exist_ok=True)
            
            success, output = self._run_command(f"cp -r {self.web_dir}/* {backup_path}/")
            
            if success:
                logger.info(f"Pre-restore backup berhasil dibuat: {backup_path}")
                return backup_path
            else:
                logger.warning(f"Gagal membuat pre-restore backup: {output}")
                return None
                
        except Exception as e:
            logger.error(f"Error membuat pre-restore backup: {e}")
            return None

    def _set_web_permissions(self):
        """Mengatur permission file web yang benar."""
        try:
            web_user = self.config.get("WEB_SERVER_USER", "www-data")
            web_group = self.config.get("WEB_SERVER_GROUP", "www-data")
            
            success, output = self._run_command(f"chown -R {web_user}:{web_group} {self.web_dir}")
            if not success:
                logger.warning(f"Gagal set ownership: {output}")
            
            success, output = self._run_command(f"chmod -R 755 {self.web_dir}")
            if not success:
                logger.warning(f"Gagal set permission: {output}")
            
            logger.info("Permission web directory diatur")
            
        except Exception as e:
            logger.error(f"Error mengatur permission: {e}")

    def _verify_restore(self):
        """Memverifikasi hasil restore."""
        try:
            if not os.path.exists(self.web_dir):
                logger.error("Direktori web tidak ditemukan setelah restore")
                return False
            
            files = os.listdir(self.web_dir)
            if not files:
                logger.error("Direktori web kosong setelah restore")
                return False
            
            important_files = ["index.html", "index.php"]
            found_important = False
            for file in important_files:
                if os.path.exists(os.path.join(self.web_dir, file)):
                    found_important = True
                    break
            
            if not found_important:
                logger.warning("File penting tidak ditemukan setelah restore")
            
            logger.info(f"Verifikasi restore berhasil. Ditemukan {len(files)} file")
            return True
            
        except Exception as e:
            logger.error(f"Error verifikasi restore: {e}")
            return False

    def manual_restore(self, backup_source="local", backup_path=None):
        """Lakukan restore manual."""
        try:
            logger.info(f"Memulai manual restore dari sumber: {backup_source}")
            
            if backup_path:
                if not os.path.exists(backup_path):
                    logger.error(f"Backup path tidak ditemukan: {backup_path}")
                    return False
                restore_path = backup_path
            else:
                restore_path = self._find_latest_backup(backup_source)
                if not restore_path:
                    logger.error(f"Tidak dapat menemukan backup untuk restore")
                    return False
            
            logger.info(f"Akan melakukan restore dari: {restore_path}")
            
            success = self._perform_restore(restore_path)
            
            if success:
                logger.info("Manual restore berhasil")
                print(f"Restore berhasil dari: {restore_path}")
                return True
            else:
                logger.error("Manual restore gagal")
                print(f"Restore gagal dari: {restore_path}")
                return False
                
        except Exception as e:
            logger.error(f"Error saat manual restore: {e}")
            print(f"Error: {e}")
            return False

    def git_restore(self, commit_id=None, is_automated_call=False):
        """Restore menggunakan Git repository."""
        if not GIT_AVAILABLE:
            error_msg = "Library gitpython tidak tersedia. Git restore dinonaktifkan."
            logger.error(error_msg)
            if not is_automated_call:
                print(Colors.FAIL + error_msg + Colors.ENDC)
            return False
            
        try:
            info_msg(f"Memulai Git restore untuk direktori: {self.web_dir}", is_automated_call)
            
            if not os.path.exists(os.path.join(self.web_dir, '.git')):
                error_exit(f"Direktori {self.web_dir} bukan Git repository")
            
            repo = git.Repo(self.web_dir)
            
            if not is_automated_call:
                self._create_pre_restore_backup()
            
            if commit_id:
                try:
                    selected_commit = repo.commit(commit_id)
                    info_msg(f"Menggunakan commit spesifik: {commit_id}", is_automated_call)
                except Exception as e:
                    error_exit(f"Commit ID '{commit_id}' tidak valid: {e}")
            else:
                commits = list(repo.iter_commits('main', max_count=10))
                if not commits:
                    error_exit("Tidak ada commit yang ditemukan")
                
                selected_commit = commits[0]
                info_msg(f"Menggunakan commit terbaru: {selected_commit.hexsha[:8]}", is_automated_call)
            
            try:
                repo.git.checkout(selected_commit.hexsha)
                info_msg(f"Git restore berhasil ke commit: {selected_commit.hexsha[:8]}", is_automated_call)
                return True
            except Exception as e:
                error_exit(f"Gagal melakukan Git restore: {e}")
                
        except Exception as e:
            logger.error(f"Error saat Git restore: {e}")
            return False

    def dynamic_restore(self, is_automated_call=False):
        """Restore file dinamis dari backup remote."""
        try:
            if self.config.get("BACKUP_DYNAMIC", "false").lower() != "true":
                info_msg("Backup dinamis tidak aktif, skip restore dinamis", is_automated_call)
                return True
            
            info_msg("Memulai restore file dinamis", is_automated_call)
            
            # Ambil arsip dinamis dari remote
            if not self._fetch_dynamic_archives():
                warning_msg("Gagal mengambil arsip dinamis dari remote", is_automated_call)
                return False
            
            # Restore file dinamis
            success = self._restore_dynamic_files(is_automated_call)
            
            if success:
                info_msg("Restore file dinamis berhasil", is_automated_call)
                return True
            else:
                warning_msg("Restore file dinamis gagal", is_automated_call)
                return False
                
        except Exception as e:
            logger.error(f"Error saat restore dinamis: {e}")
            return False

    def _fetch_dynamic_archives(self):
        """Mengambil arsip dinamis dari server remote."""
        try:
            if not self.monitoring_server or not self.monitoring_user:
                logger.error("Konfigurasi server monitoring tidak lengkap")
                return False
            
            # Direktori cache untuk arsip dinamis
            cache_dir = self.config.get("LOCAL_DYNAMIC_RESTORE_CACHE_DIR", "/tmp/soc-dynamic-restore-cache")
            os.makedirs(cache_dir, exist_ok=True)
            
            # Ambil arsip dinamis terbaru dari remote
            remote_dynamic_path = self.config.get("REMOTE_DYNAMIC_BACKUP_PATH", "/home/soc-backup/dynamic-backup")
            command = f"scp {self.monitoring_user}@{self.monitoring_server}:{remote_dynamic_path}/*.tar.gz {cache_dir}/"
            
            success, output = self._run_command(command)
            
            if success:
                logger.info("Arsip dinamis berhasil diambil dari remote")
                return True
            else:
                logger.error(f"Gagal mengambil arsip dinamis: {output}")
                return False
                
        except Exception as e:
            logger.error(f"Error mengambil arsip dinamis: {e}")
            return False

    def _restore_dynamic_files(self, is_automated_call=False):
        """Restore file dinamis dari cache."""
        try:
            cache_dir = self.config.get("LOCAL_DYNAMIC_RESTORE_CACHE_DIR", "/tmp/soc-dynamic-restore-cache")
            
            # Cari arsip dinamis terbaru
            archive_files = glob.glob(os.path.join(cache_dir, "*.tar.gz"))
            if not archive_files:
                warning_msg("Tidak ada arsip dinamis yang ditemukan", is_automated_call)
                return False
            
            # Pilih arsip terbaru
            latest_archive = max(archive_files, key=os.path.getctime)
            info_msg(f"Menggunakan arsip dinamis: {os.path.basename(latest_archive)}", is_automated_call)
            
            # Extract arsip
            success, output = self._run_command(f"tar -xzf {latest_archive} -C {self.web_dir}")
            
            if success:
                logger.info("File dinamis berhasil di-restore")
                return True
            else:
                logger.error(f"Gagal extract file dinamis: {output}")
                return False
                
        except Exception as e:
            logger.error(f"Error restore file dinamis: {e}")
            return False

def verify_password_interactive(stored_password_b64):
    """Verifikasi password secara interaktif."""
    try:
        stored_password = base64.b64decode(stored_password_b64).decode('utf-8')
        max_attempts = 3
        
        for attempt in range(max_attempts):
            password = getpass.getpass(f"Masukkan password untuk restore (percobaan {attempt + 1}/{max_attempts}): ")
            if password == stored_password:
                return True
            else:
                print(Colors.FAIL + "Password salah!" + Colors.ENDC)
        
        error_exit("Password salah setelah 3 percobaan. Operasi dibatalkan.")
        
    except Exception as e:
        error_exit(f"Error verifikasi password: {e}")

def main():
    """Main function untuk Unified Restore."""
    parser = argparse.ArgumentParser(description="SOC Unified Restore Tool - NIST 800-61 Recovery Phase")
    parser.add_argument("--alert", type=str, help="Data alert dari Wazuh dalam format JSON (mode auto)")
    parser.add_argument("--auto", action="store_true", help="Mode otomatis penuh")
    parser.add_argument("--manual", action="store_true", help="Mode manual interaktif")
    parser.add_argument("--backup-source", choices=["local", "remote"], default="local", help="Sumber backup (default: local)")
    parser.add_argument("--backup-path", type=str, help="Path backup spesifik")
    parser.add_argument("--commit", type=str, help="ID commit spesifik untuk Git restore")
    parser.add_argument("--git-only", action="store_true", help="Restore Git saja, skip file dinamis")
    parser.add_argument("--dynamic-only", action="store_true", help="Restore file dinamis saja, skip Git")
    args = parser.parse_args()
    
    # Tentukan mode operasi
    is_automated_call = args.auto or bool(args.alert)
    
    if not is_automated_call and not args.manual:
        print_banner()
    
    # Cek root privileges
    if os.geteuid() != 0:
        error_exit("Script ini perlu dijalankan sebagai root untuk operasi file sistem.")
    
    # Inisialisasi restore manager
    restore_manager = UnifiedRestoreManager(mode="auto" if is_automated_call else "manual")
    
    # Mode Auto (Wazuh Active Response)
    if args.alert:
        try:
            success = restore_manager.process_wazuh_alert(args.alert)
            if success:
                print("Auto restore berhasil")
                sys.exit(0)
            else:
                print("Auto restore gagal")
                sys.exit(1)
        except Exception as e:
            logger.error(f"Error dalam auto restore: {e}")
            print(f"Error: {e}")
            sys.exit(1)
    
    # Mode Auto (Command line)
    elif args.auto:
        try:
            # Verifikasi password jika diperlukan
            if restore_manager.config.get("PASSWORD"):
                verify_password_interactive(restore_manager.config["PASSWORD"])
            
            # Restore Git
            git_success = True
            if not args.dynamic_only:
                git_success = restore_manager.git_restore(args.commit, is_automated_call=True)
            
            # Restore dinamis
            dynamic_success = True
            if not args.git_only:
                dynamic_success = restore_manager.dynamic_restore(is_automated_call=True)
            
            if git_success and dynamic_success:
                print("Auto restore berhasil")
                sys.exit(0)
            else:
                print("Auto restore gagal")
                sys.exit(1)
                
        except Exception as e:
            logger.error(f"Error dalam auto restore: {e}")
            print(f"Error: {e}")
            sys.exit(1)
    
    # Mode Manual (Interactive)
    else:
        try:
            # Verifikasi password
            if restore_manager.config.get("PASSWORD"):
                verify_password_interactive(restore_manager.config["PASSWORD"])
            
            # Pilihan restore
            print("\n" + Colors.BOLD + "Pilihan Restore:" + Colors.ENDC)
            print("1. Restore dari backup file/direktori")
            print("2. Restore Git repository")
            print("3. Restore file dinamis")
            print("4. Restore lengkap (Git + Dinamis)")
            
            choice = input("\nPilih opsi (1-4): ").strip()
            
            if choice == "1":
                # Restore dari backup
                backup_source = input("Sumber backup (local/remote) [local]: ").strip() or "local"
                backup_path = input("Path backup spesifik (kosongkan untuk otomatis): ").strip() or None
                
                success = restore_manager.manual_restore(backup_source, backup_path)
                if success:
                    print("Restore dari backup berhasil")
                else:
                    print("Restore dari backup gagal")
                    
            elif choice == "2":
                # Restore Git
                commit_id = input("ID commit spesifik (kosongkan untuk terbaru): ").strip() or None
                success = restore_manager.git_restore(commit_id, is_automated_call=False)
                if success:
                    print("Git restore berhasil")
                else:
                    print("Git restore gagal")
                    
            elif choice == "3":
                # Restore dinamis
                success = restore_manager.dynamic_restore(is_automated_call=False)
                if success:
                    print("Restore file dinamis berhasil")
                else:
                    print("Restore file dinamis gagal")
                    
            elif choice == "4":
                # Restore lengkap
                commit_id = input("ID commit spesifik (kosongkan untuk terbaru): ").strip() or None
                
                git_success = restore_manager.git_restore(commit_id, is_automated_call=False)
                dynamic_success = restore_manager.dynamic_restore(is_automated_call=False)
                
                if git_success and dynamic_success:
                    print("Restore lengkap berhasil")
                else:
                    print("Restore lengkap gagal")
                    
            else:
                print("Pilihan tidak valid")
                sys.exit(1)
                
        except KeyboardInterrupt:
            print("\nOperasi dibatalkan oleh user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error dalam manual restore: {e}")
            print(f"Error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main() 