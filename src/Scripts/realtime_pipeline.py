"""Main entry point for the real-time IDPS pipeline."""

import warnings
import datetime
import sqlite3
from scapy.all import sniff, IP, TCP, UDP, ICMP

import sys
import os

# Ensure the root project directory (parent of src) is in sys.path
# so that absolute imports like `from src.config` work perfectly.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.config import DB_PATH, BLOCK_DURATION_MINUTES
from src.Database.database import init_db, log_alert, log_blocked_ip, load_blocked_ips
from src.Scripts.firewall import block_ip, unblock_ip
from src.Scripts.features import extract_features, preprocess_features
from src.Scripts.model_loader import load_models

warnings.filterwarnings('ignore')

def start_pipeline():
    init_db()
    model, scaler, model_columns = load_models()
    
    if model is None:
        print("Cannot start pipeline without a valid model.")
        return

    blocked_ips = load_blocked_ips()

    def packet_callback(packet):
        """Callback function executed for each captured packet."""
        if IP not in packet:
            return
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Determine protocol for logging
        protocol = 'unknown'
        if TCP in packet: protocol = 'tcp'
        elif UDP in packet: protocol = 'udp'
        elif ICMP in packet: protocol = 'icmp'
        
        # Check expiry of blocked IPs
        if src_ip in blocked_ips:
            if datetime.datetime.now().timestamp() > blocked_ips[src_ip]:
                unblock_ip(src_ip)
                del blocked_ips[src_ip]
                # Also remove from DB
                try:
                    conn = sqlite3.connect(DB_PATH)
                    conn.cursor().execute('DELETE FROM blocked_ips WHERE ip = ?', (src_ip,))
                    conn.commit()
                    conn.close()
                except:
                    pass
            else:
                return
        elif src_ip == '127.0.0.1':
            return
            
        features_dict = extract_features(packet)
        
        try:
            processed_data = preprocess_features(features_dict, scaler, model_columns)
            
            prediction = model.predict(processed_data)
            
            # Interpret prediction: assume 'normal' or 0 is benign, anything else is malicious
            is_malicious = False
            if isinstance(prediction[0], str):
                is_malicious = prediction[0] != 'normal'
            else:
                is_malicious = prediction[0] != 0
                
            if is_malicious:
                prediction_val = str(prediction[0])
                print(f"[*] Malicious packet detected from {src_ip} (Prediction: {prediction_val})")
                action_taken = "Blocked"
                block_ip(src_ip)
                
                # Log to SQLite and get expiry timestamp
                log_alert(src_ip, dst_ip, protocol, prediction_val, action_taken)
                expiry_ts = log_blocked_ip(src_ip, BLOCK_DURATION_MINUTES)
                blocked_ips[src_ip] = expiry_ts
                
        except Exception as e:
            # print(f"Error processing packet: {e}")
            pass

    print("\n[+] Starting real-time Intrusion Detection System...")
    print("[+] Capturing packets. Press Ctrl+C to stop.")
    
    # Start sniffing
    # You can specify an interface with iface='eth0' or a BPF filter like filter="ip"
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_pipeline()
