"""Manages SQLite database logging and expiry loading."""

import sys
import os

# Ensure the project root is in sys.path so that absolute imports work
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import sqlite3
import datetime
from src.config import DB_PATH
from src.Scripts.firewall import unblock_ip


def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            prediction TEXT,
            action TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            block_time TEXT,
            expiry_time TEXT
        )
    ''')
    conn.commit()
    conn.close()


def log_alert(src_ip, dst_ip, protocol, prediction, action):
    """Logs an alert to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, protocol, prediction, action)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, protocol, prediction, action))
    conn.commit()
    conn.close()


def log_blocked_ip(ip, duration_minutes):
    """Logs a blocked IP to the SQLite database and returns the expiry timestamp."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.datetime.now()
    expiry = now + datetime.timedelta(minutes=duration_minutes)
    cursor.execute('''
        INSERT OR REPLACE INTO blocked_ips (ip, block_time, expiry_time)
        VALUES (?, ?, ?)
    ''', (now.strftime("%Y-%m-%d %H:%M:%S"), expiry.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return expiry.timestamp()


def load_blocked_ips():
    """Loads active blocks from the database and unblocks expired ones."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    blocked = {}
    try:
        cursor.execute('SELECT ip, expiry_time FROM blocked_ips')
        rows = cursor.fetchall()
        now = datetime.datetime.now()
        for ip, expiry_str in rows:
            expiry = datetime.datetime.strptime(
                expiry_str, "%Y-%m-%d %H:%M:%S")
            if now > expiry:
                unblock_ip(ip)
                cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
            else:
                blocked[ip] = expiry.timestamp()
        conn.commit()
    except Exception as e:
        print(f"[-] Error loading blocked IPs from DB: {e}")
    finally:
        conn.close()
    return blocked
