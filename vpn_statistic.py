#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Автоматическая синхронизация статистики VPN (WireGuard, OpenVPN и др.)
с определением типа и провайдера, с LLHost и HostSlim.
TechHarbor Pte. Ltd.
"""

import os
import re
import subprocess
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta, UTC
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from pathlib import Path
import logging
import traceback

# === Логирование ===
LOG_FILE = "/var/log/vpn_sync.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='[%(asctime)s] %(message)s')

def log(msg):
    print(msg)
    logging.info(msg)

# === 1. Загрузка окружения ===
ENV_PATHS = ["/opt/backups/scripts/.env", "/opt/techharbor/.env", ".env"]
for env_path in ENV_PATHS:
    if os.path.exists(env_path):
        load_dotenv(env_path)
        break

DB_NAME = os.getenv("POSTGRES_DB", "services")
DB_USER = os.getenv("POSTGRES_USER", "vpnagent")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY не найден в .env!")

fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
VPN_BASE_DIR = Path("/etc")

# === 2. Словари ===
VPN_DETECT = {
    "interface_prefix": {
        "wg": "WireGuard",
        "tun": "OpenVPN",
        "tap": "OpenVPN",
        "ppp": "PPPoE",
        "vti": "IPsec",
        "zt": "ZeroTier",
        "tailscale": "Tailscale",
    },
    "providers": {
        "5.188.51.59": "LLHost",
        "69.174.98.37": "HostSlim",
        "185.22.11.": "MakeCloud",
    }
}

REMOTE_SERVERS = {
    "LLHost": {"host": "localhost"},
    "HostSlim": {"host": "69.174.98.37", "port": 5234},
}

# === 3. Функции ===
def detect_soft_from_interface(interface_name: str):
    """Определяет тип VPN по имени интерфейса"""
    for prefix, vpn_type in VPN_DETECT["interface_prefix"].items():
        if interface_name.startswith(prefix):
            return vpn_type
    return "Unknown"


def list_vpn_interfaces(host: str = "localhost", port: int = 22):
    """Возвращает список интерфейсов VPN любого типа (локально или по SSH)"""
    if host in ("localhost", "127.0.0.1"):
        cmd = ["ip", "-brief", "link", "show"]
    else:
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-p", str(port),
            f"root@{host}",
            "ip -brief link show"
        ]
    
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).splitlines()
        vpn_ifaces = []
        vpn_prefixes = tuple(VPN_DETECT["interface_prefix"].keys())
        for line in output:
            name = line.split()[0]
            # Убираем @NONE и подобные суффиксы
            name = name.split("@")[0]
            if any(name.startswith(prefix) for prefix in vpn_prefixes):
                vpn_ifaces.append(name)
        return vpn_ifaces
    except Exception as e:
        log(f"⚠️  Ошибка получения интерфейсов с {host}: {e}")
        return []


def find_clients_dir(interface: str, host: str = "localhost", port: int = 22):
    """Ищет директорию с клиентами для данного интерфейса"""
    # Возможные пути
    possible_paths = [
        f"/etc/{interface}/clients",
        f"/etc/wireguard/clients",
        f"/etc/openvpn/clients",
    ]
    
    for path in possible_paths:
        if host in ("localhost", "127.0.0.1"):
            if Path(path).exists():
                return Path(path)
        else:
            # Проверяем по SSH
            cmd = [
                "ssh",
                "-o", "BatchMode=yes",
                "-p", str(port),
                f"root@{host}",
                f"test -d {path} && echo EXISTS"
            ]
            try:
                result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
                if result == "EXISTS":
                    return path  # Возвращаем строку для удаленного пути
            except Exception:
                continue
    return None


def list_conf_files(clients_dir, host: str = "localhost", port: int = 22):
    """Возвращает список .conf файлов в директории клиентов"""
    conf_files = []
    
    if host in ("localhost", "127.0.0.1"):
        clients_path = Path(clients_dir)
        if clients_path.exists():
            # Ищем .conf файлы в поддиректориях
            for folder in clients_path.iterdir():
                if folder.is_dir():
                    for conf_file in folder.glob("*.conf"):
                        conf_files.append({
                            "path": conf_file,
                            "code": folder.name,
                            "is_local": True
                        })
    else:
        # Удаленный сервер
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-p", str(port),
            f"root@{host}",
            f"find {clients_dir} -type f -name '*.conf'"
        ]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
            for line in output.splitlines():
                # Извлекаем code из пути (имя родительской папки)
                parts = line.split("/")
                if len(parts) >= 2:
                    code = parts[-2]  # Родительская директория
                    conf_files.append({
                        "path": line,
                        "code": code,
                        "is_local": False,
                        "host": host,
                        "port": port
                    })
        except Exception as e:
            log(f"⚠️  Ошибка получения списка конфигов с {host}:{clients_dir}: {e}")
    
    return conf_files


def read_remote_conf(file_path: str, host: str, port: int = 22) -> dict:
    """Читает .conf файл с удаленного сервера"""
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-p", str(port),
        f"root@{host}",
        f"cat {file_path}"
    ]
    try:
        raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        cleaned = bytes(b for b in raw if 32 <= b <= 126 or b in (10, 13))
        content = cleaned.decode("ascii", errors="ignore")
        
        keys = [
            "PrivateKey", "PublicKey", "PresharedKey",
            "Address", "AllowedIPs", "Endpoint", "DNS", "PersistentKeepalive"
        ]
        fields = {}
        for key_name in keys:
            # Берем все до конца строки, убирая пробелы в начале и конце
            match = re.search(rf"{key_name}\s*=\s*(.+?)$", content, re.MULTILINE)
            if match:
                fields[key_name.lower()] = match.group(1).strip()
        return fields
    except Exception as e:
        log(f"⚠️  Ошибка чтения удаленного файла {file_path}: {e}")
        return {}


def get_file_creation_time(file_path, host: str = "localhost", port: int = 22):
    """Получает дату создания файла (локально или удаленно)"""
    try:
        if host in ("localhost", "127.0.0.1"):
            # Локальный файл
            if isinstance(file_path, str):
                file_path = Path(file_path)
            stat = file_path.stat()
            # Используем mtime (время модификации), так как в Linux нет надежного ctime
            return datetime.fromtimestamp(stat.st_mtime, UTC)
        else:
            # Удаленный файл - получаем timestamp через SSH
            cmd = [
                "ssh",
                "-o", "BatchMode=yes",
                "-p", str(port),
                f"root@{host}",
                f"stat -c %Y {file_path}"
            ]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
            timestamp = int(output)
            return datetime.fromtimestamp(timestamp, UTC)
    except Exception as e:
        log(f"⚠️  Не удалось получить дату создания {file_path}: {e}")
        return None


def db_connect():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        cursor_factory=RealDictCursor
    )


def parse_conf(file_path: Path) -> dict:
    """Извлекает ключевые поля из .conf"""
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
        cleaned = bytes(b for b in raw if 32 <= b <= 126 or b in (10, 13))
        content = cleaned.decode("ascii", errors="ignore")
    except Exception as e:
        log(f"⚠️  Ошибка чтения {file_path}: {e}")
        return {}

    keys = [
        "PrivateKey", "PublicKey", "PresharedKey",
        "Address", "AllowedIPs", "Endpoint", "DNS", "PersistentKeepalive"
    ]
    fields = {}
    for key_name in keys:
        # Берем все до конца строки, убирая пробелы в начале и конце
        match = re.search(rf"{key_name}\s*=\s*(.+?)$", content, re.MULTILINE)
        if match:
            fields[key_name.lower()] = match.group(1).strip()
    return fields


def parse_handshake(value: str):
    try:
        ts = int(value)
        if ts > 0:
            return datetime.fromtimestamp(ts, UTC)
        return None
    except ValueError:
        pass

    if "ago" not in value:
        return None

    value = value.replace(" ago", "").strip()
    parts = value.split(",")
    total_seconds = 0
    for part in parts:
        part = part.strip()
        try:
            num, unit = part.split()[:2]
            num = int(num)
        except Exception:
            continue
        if "second" in unit:
            total_seconds += num
        elif "minute" in unit:
            total_seconds += num * 60
        elif "hour" in unit:
            total_seconds += num * 3600
        elif "day" in unit:
            total_seconds += num * 86400

    return datetime.now(UTC) - timedelta(seconds=total_seconds)


def get_wg_dump(host: str, interface: str, port: int = 22) -> list[str]:
    """Возвращает вывод wg show <interface> dump локально или по SSH"""
    if host in ("localhost", "127.0.0.1"):
        cmd = ["wg", "show", interface, "dump"]
    else:
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-p", str(port),
            f"root@{host}",
            f"wg show {interface} dump"
        ]
    try:
        raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return raw.decode("utf-8", errors="ignore").strip().splitlines()
    except Exception as e:
        log(f"⚠️  Не удалось получить dump с {host}:{interface}: {e}")
        return []


def parse_wg_output(output, interface: str):
    """Парсит вывод wg show dump и возвращает статистику по code (публичным ключам)"""
    stats = {}
    for i, line in enumerate(output):
        parts = line.split("\t")
        if i == 0 and len(parts) == 4:
            # Это заголовок интерфейса, пропускаем
            continue
        if len(parts) < 8:
            continue

        public_key, preshared_key, endpoint_client, allowed_ips, last_hs, rx, tx, keepalive = parts
        last_seen = parse_handshake(last_hs)
        try:
            rx, tx = int(rx), int(tx)
        except Exception:
            rx = tx = 0
        
        # Используем публичный ключ как идентификатор
        stats[public_key] = {
            "last_seen": last_seen,
            "rx": rx,
            "tx": tx,
            "interface": interface,
            "endpoint_client": endpoint_client if endpoint_client != "(none)" else None
        }
    return stats


def collect_stats():
    """Собирает статистику со всех серверов и их интерфейсов"""
    all_stats = {}
    
    for provider, info in REMOTE_SERVERS.items():
        host = info["host"]
        port = info.get("port", 22)
        
        # Получаем список VPN интерфейсов на сервере
        interfaces = list_vpn_interfaces(host, port)
        log(f"🔍 {provider}: найдено интерфейсов: {len(interfaces)} — {interfaces}")
        
        for interface in interfaces:
            # Собираем статистику для каждого интерфейса
            soft = detect_soft_from_interface(interface)
            
            # Пока поддерживаем только WireGuard для статистики
            if not soft.startswith("WireGuard"):
                log(f"⚠️  Пропуск {interface} ({soft}) — статистика поддерживается только для WireGuard")
                continue
            
            output = get_wg_dump(host, interface, port)
            if not output:
                continue
                
            parsed = parse_wg_output(output, interface)
            log(f"📊 {provider}/{interface}: собрано {len(parsed)} записей статистики")
            
            # Сохраняем с ключом (provider, interface, public_key)
            for pub_key, stats in parsed.items():
                key = (provider, interface, pub_key)
                all_stats[key] = stats
    
    total_active = sum(1 for s in all_stats.values() if s["last_seen"])
    log(f"✅ Всего собрано {len(all_stats)} записей VPN (активных: {total_active})")
    return all_stats


def sync_clients(conn):
    """Синхронизирует VPN-клиенты со всех серверов и интерфейсов"""
    cur = conn.cursor()
    
    # Получаем существующие коды для проверки дубликатов
    cur.execute("SELECT code FROM vpnusers;")
    existing_codes = {row["code"] for row in cur.fetchall()}
    
    added = 0
    total = 0
    
    # Проходим по всем серверам
    for provider, info in REMOTE_SERVERS.items():
        host = info["host"]
        port = info.get("port", 22)
        
        log(f"🔄 Обработка сервера: {provider} ({host})")
        
        # Получаем список VPN интерфейсов на сервере
        interfaces = list_vpn_interfaces(host, port)
        
        for interface in interfaces:
            soft = detect_soft_from_interface(interface)
            log(f"  📡 Интерфейс: {interface} ({soft})")
            
            # Ищем директорию с клиентами
            clients_dir = find_clients_dir(interface, host, port)
            if not clients_dir:
                log(f"    ⚠️  Директория с клиентами не найдена для {interface}")
                continue
            
            log(f"    📂 Найдена директория: {clients_dir}")
            
            # Получаем список .conf файлов
            conf_files = list_conf_files(clients_dir, host, port)
            log(f"    📄 Найдено конфигов: {len(conf_files)}")
            
            for conf_info in conf_files:
                total += 1
                code = conf_info["code"]
                
                # Проверяем, существует ли уже клиент с таким code
                if code in existing_codes:
                    continue
                
                # Читаем конфигурационный файл
                if conf_info["is_local"]:
                    data = parse_conf(conf_info["path"])
                else:
                    data = read_remote_conf(conf_info["path"], conf_info["host"], conf_info["port"])
                
                if not data:
                    log(f"    ⚠️  Не удалось разобрать конфиг для {code}")
                    continue
                
                # Шифруем ключи
                enc_private = fernet.encrypt(data["privatekey"].encode()).decode() if data.get("privatekey") else None
                enc_public = fernet.encrypt(data["publickey"].encode()).decode() if data.get("publickey") else None
                enc_preshared = fernet.encrypt(data["presharedkey"].encode()).decode() if data.get("presharedkey") else None
                
                # Получаем остальные поля
                address = data.get("address")
                allowed_ips = data.get("allowedips")
                endpoint = data.get("endpoint")
                dns = data.get("dns")
                keepalive = data.get("persistentkeepalive")
                
                # Получаем дату создания файла
                if conf_info["is_local"]:
                    file_created_at = get_file_creation_time(conf_info["path"])
                else:
                    file_created_at = get_file_creation_time(conf_info["path"], conf_info["host"], conf_info["port"])
                
                # Вставляем клиента в БД
                cur.execute("""
                    INSERT INTO vpnusers (
                        code, address,
                        private_key, public_key, preshared_key,
                        allowed_ips, endpoint, dns, persistent_keepalive,
                        soft, provider1, interface, created_at
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (code) DO NOTHING;
                """, (
                    code, address,
                    enc_private, enc_public, enc_preshared,
                    allowed_ips, endpoint, dns, keepalive,
                    soft, provider, interface, file_created_at
                ))
                
                if cur.rowcount > 0:
                    added += 1
                    existing_codes.add(code)
                    log(f"    ➕ Добавлен: {code} ({address}) — {soft}/{provider}/{interface}")
    
    conn.commit()
    cur.close()
    log(f"✅ Синхронизация завершена. Всего обработано: {total}, добавлено: {added}")

def update_stats(conn, stats):
    """Обновляет статистику VPN-клиентов"""
    cur = conn.cursor()
    updated = 0
    not_found = 0
    
    # Получаем всех клиентов с их зашифрованными публичными ключами
    cur.execute("SELECT code, public_key, interface, provider1 FROM vpnusers WHERE public_key IS NOT NULL;")
    clients = cur.fetchall()
    
    # Создаем словарь расшифрованных ключей для быстрого поиска
    decrypted_keys = {}
    for client in clients:
        try:
            encrypted_key = client["public_key"]
            if encrypted_key:
                decrypted_key = fernet.decrypt(encrypted_key.encode()).decode()
                # Ключ: (provider, interface, decrypted_public_key)
                key = (client["provider1"], client["interface"], decrypted_key)
                decrypted_keys[key] = client["code"]
        except Exception as e:
            log(f"⚠️  Ошибка расшифровки ключа для {client['code']}: {e}")
            continue
    
    log(f"🔑 Расшифровано {len(decrypted_keys)} публичных ключей")
    
    # Обновляем статистику
    for key, s in stats.items():
        provider, interface, public_key = key
        
        # Ищем клиента по ключу
        lookup_key = (provider, interface, public_key)
        if lookup_key in decrypted_keys:
            code = decrypted_keys[lookup_key]
            # Обновляем статистику
            cur.execute("""
                UPDATE vpnusers
                   SET last_seen = %s,
                       transfer_rx = %s,
                       transfer_tx = %s,
                       endpoint_client = %s
                 WHERE code = %s;
            """, (s["last_seen"], s["rx"], s["tx"], s.get("endpoint_client"), code))
            if cur.rowcount > 0:
                updated += 1
        else:
            not_found += 1
            # Для отладки
            log(f"⚠️  Не найден клиент для ключа: {public_key[:20]}... на {provider}/{interface}")
    
    conn.commit()
    cur.close()
    log(f"✅ Обновлено {updated} записей статистики VPN (не найдено: {not_found})")


def main():
    log("=== [VPN STATISTICS SYNC STARTED] ===")
    conn = db_connect()
    try:
        # Синхронизируем клиентов со всех серверов
        sync_clients(conn)
        
        # Собираем статистику
        stats = collect_stats()
        
        # Обновляем статистику в БД
        update_stats(conn, stats)
        
        log("=== [SYNC COMPLETE] ===")
    except Exception as e:
        log(f"❌ Ошибка: {e}")
        log(traceback.format_exc())
    finally:
        conn.close()


if __name__ == "__main__":
    main()

