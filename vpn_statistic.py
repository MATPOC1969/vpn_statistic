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
CLIENTS_DIR = Path("/etc/wireguard/clients")

# === 2. Словари ===
VPN_DETECT = {
    "interface_prefix": {
        "wg": "WireGuard",
        "tun": "OpenVPN",
        "tap": "OpenVPN",
    },
    "providers": {
        "5.188.51.59": "LLHost",
        "69.174.98.37": "HostSlim",
        "185.22.11.": "MakeCloud",
    }
}

REMOTE_SERVERS = {
    "LLHost": {"host": "localhost", "interface": "wg0"},
    "HostSlim": {"host": "69.174.98.37", "interface": "wg0", "port": 5234},
}

# === 3. Функции ===
def detect_soft_provider(interface_name: str, endpoint: str):
    soft = "Unknown"
    provider = "Unknown"
    for prefix, vpn_type in VPN_DETECT["interface_prefix"].items():
        if interface_name.startswith(prefix):
            soft = vpn_type
            break
    for pattern, prov in VPN_DETECT["providers"].items():
        if pattern in endpoint:
            provider = prov
            break
    return soft, provider


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
        match = re.search(rf"{key_name}\s*=\s*(\S+)", content)
        if match:
            fields[key_name.lower()] = match.group(1)
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
        log(f"⚠️  Не удалось получить dump с {host}: {e}")
        return []


def parse_wg_output(output, provider_label="Unknown"):
    stats = {}
    for i, line in enumerate(output):
        parts = line.split("\t")
        if i == 0 and len(parts) == 4:
            continue
        if len(parts) < 8:
            continue

        public_key, preshared_key, endpoint, allowed_ips, last_hs, rx, tx, keepalive = parts
        ip = allowed_ips.split("/")[0]
        last_seen = parse_handshake(last_hs)
        try:
            rx, tx = int(rx), int(tx)
        except Exception:
            rx = tx = 0
        stats[ip] = {
            "public_key": public_key,
            "last_seen": last_seen,
            "rx": rx,
            "tx": tx,
            "endpoint": endpoint,
            "provider": provider_label
        }
    return stats


def collect_stats():
    all_stats = {}
    for provider, info in REMOTE_SERVERS.items():
        host = info["host"]
        interface = info["interface"]
        port = info.get("port", 22)
        output = get_wg_dump(host, interface, port)
        log(f"Сбор статистики с {provider} ({interface}) — строк: {len(output)}")
        parsed = parse_wg_output(output, provider)
        all_stats.update(parsed)
    total_active = sum(1 for s in all_stats.values() if s["last_seen"])
    log(f"Собрано {len(all_stats)} записей VPN (активных: {total_active}).")
    return all_stats


def sync_clients(conn, stats_from_remote=None):
    """Синхронизирует локальные VPN-клиенты и новые IP с удалённых серверов."""
    cur = conn.cursor()
    cur.execute("SELECT code, address FROM vpnusers;")
    existing_addresses = {row["address"]: row["code"] for row in cur.fetchall()}

    added = 0
    total = 0

    # --- 1. Локальные конфиги ---
    for folder in CLIENTS_DIR.iterdir():
        if not folder.is_dir():
            continue
        total += 1
        code = folder.name
        conf_file = next(folder.glob("*.conf"), None)
        if not conf_file:
            log(f"⚠️  В {folder} нет .conf — пропуск")
            continue

        data = parse_conf(conf_file)
        if not data:
            log(f"⚠️  Не удалось разобрать {conf_file}")
            continue

        address = data.get("address", "").split("/")[0] if data.get("address") else None
        if address in existing_addresses:
            log(f"✔️  Клиент уже есть: {code}")
            continue

        # --- шифруем ключи ---
        enc_private = fernet.encrypt(data["privatekey"].encode()).decode() if data.get("privatekey") else None
        enc_public = fernet.encrypt(data["publickey"].encode()).decode() if data.get("publickey") else None
        enc_preshared = fernet.encrypt(data["presharedkey"].encode()).decode() if data.get("presharedkey") else None

        # --- дополнительные поля ---
        allowed_ips = data.get("allowedips")
        endpoint = data.get("endpoint", "")
        dns = data.get("dns")
        keepalive = data.get("persistentkeepalive")

        soft, provider = detect_soft_provider("wg0", endpoint)

        cur.execute("""
            INSERT INTO vpnusers (
                code, address,
                private_key, public_key, preshared_key,
                allowed_ips, endpoint, dns, persistent_keepalive,
                soft, provider1, created_at
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW());
        """, (
            code, address,
            enc_private, enc_public, enc_preshared,
            allowed_ips, endpoint, dns, keepalive,
            soft, provider
        ))

        added += 1
        log(f"➕ Добавлен новый клиент: {code} ({address}) — {soft}/{provider}")

    # --- 2. Добавляем новые IP, найденные на удалённых серверах ---
    if stats_from_remote:
        for ip, s in stats_from_remote.items():
            # проверяем, есть ли уже в базе клиент с таким адресом
            if ip in existing_addresses:
                continue

            code_auto = f"AUTO_{ip.replace('.', '_')}"
            # проверяем, нет ли в базе клиента с таким же code
            cur.execute("SELECT 1 FROM vpnusers WHERE code = %s;", (code_auto,))
            if cur.fetchone():
                continue

            soft, provider = detect_soft_provider("wg0", s["endpoint"])
            cur.execute("""
                INSERT INTO vpnusers (code, address, soft, provider1, created_at)
                VALUES (%s, %s, %s, %s, NOW());
            """, (code_auto, ip, soft, provider))
            added += 1
            log(f"➕ Добавлен новый клиент (из {s['provider']}): {ip}")
    
    conn.commit()
    cur.close()
    log(f"✅ Синхронизация завершена. Всего локальных: {total}, добавлено: {added}")

def update_stats(conn, stats):
    cur = conn.cursor()
    updated = 0
    for ip, s in stats.items():
        for variant in (ip, f"{ip}/32"):
            cur.execute("""
                UPDATE vpnusers
                   SET last_seen = %s,
                       transfer_rx = %s,
                       transfer_tx = %s,
                       provider1 = %s
                 WHERE address = %s;
            """, (s["last_seen"], s["rx"], s["tx"], s["provider"], variant))
            if cur.rowcount:
                updated += cur.rowcount
                break
    conn.commit()
    cur.close()
    log(f"✅ Обновлено {updated} записей статистики VPN.")


def main():
    log("=== [VPN STATISTICS SYNC STARTED] ===")
    conn = db_connect()
    try:
        stats = collect_stats()
        sync_clients(conn, stats_from_remote=stats)
        update_stats(conn, stats)
        log("=== [SYNC COMPLETE] ===")
    except Exception as e:
        log(f"❌ Ошибка: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()

